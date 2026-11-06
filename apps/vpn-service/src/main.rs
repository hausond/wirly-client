use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use vpn_config::parse_uri;
use vpn_core::Session;
use vpn_dns::FakeIpPool;
use vpn_routing::{ConnectionInfo, Network, Preset, RoutingEngine};

fn main() -> Result<()> {
    println!("hausond vpn — scaffold build");
    println!("============================\n");

    let dir = presets_dir().context("presets directory not found")?;
    let mut loaded = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let raw = std::fs::read_to_string(&path)?;
            let preset = Preset::from_json(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            println!(
                "preset `{}` ({} rules) — {}",
                preset.name,
                preset.rules.len(),
                preset.description
            );
            loaded.push(preset);
        }
    }
    println!();

    let preset = loaded
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case("Bypass RU"))
        .or_else(|| loaded.first())
        .context("no presets found")?;
    let engine = RoutingEngine::new(preset)?;
    println!(
        "routing with `{}`, {} rules\n",
        preset.name,
        engine.rule_count()
    );

    let samples: [(&str, ConnectionInfo<'_>); 4] = [
        (
            "youtube.com:443",
            ConnectionInfo::tcp(ip("142.250.74.46"), 443).with_domain("www.youtube.com"),
        ),
        ("LAN 10.1.2.3:80", ConnectionInfo::tcp(ip("10.1.2.3"), 80)),
        (
            "Wow.exe -> 8.8.8.8:443",
            ConnectionInfo::tcp(ip("8.8.8.8"), 443).with_process("Wow.exe"),
        ),
        (
            "DNS 1.1.1.1:53/udp",
            ConnectionInfo {
                domain: None,
                ip: Some(ip("1.1.1.1")),
                port: 53,
                process: None,
                network: Network::Udp,
            },
        ),
    ];

    println!("{:<28} {:<22} reason", "connection", "action");
    println!("{}", "-".repeat(64));
    for (label, conn) in &samples {
        let decision = engine.decide(conn);
        println!(
            "{:<28} {:<22} {}",
            label,
            format!("{:?}", decision.action),
            decision.reason()
        );
    }
    println!();

    // Share-link import demo.
    let uri = "vless://98d47ea6-7c92-4693-aff2-4b2a381c71de@91.192.157.137:443?type=ws&path=%2Fws-50ada98a&security=tls&sni=91.192.157.137&host=91.192.157.137&fp=chrome#vpn-Nikita-ws";
    let profile = parse_uri(uri).context("failed to parse demo URI")?;
    println!(
        "parsed share link: `{}` -> {:?}",
        profile.name, profile.protocol
    );

    let mut session = Session::new();
    session.begin_connect(profile)?;
    session.mark_connected()?;
    session.add_traffic(1024, 4096);
    println!(
        "session state: {:?}, stats: {:?}",
        session.state(),
        session.stats()
    );

    let mut pool = FakeIpPool::new();
    let fake = pool.allocate("discord.com");
    println!(
        "fake-ip: discord.com -> {fake}, reverse -> {:?}",
        pool.domain_for(IpAddr::V4(fake))
    );

    Ok(())
}

fn ip(raw: &str) -> IpAddr {
    raw.parse().expect("hard-coded sample IP")
}

fn presets_dir() -> Option<PathBuf> {
    let candidates = [
        Path::new("presets").to_path_buf(),
        Path::new("../presets").to_path_buf(),
        Path::new("../../presets").to_path_buf(),
    ];
    candidates.into_iter().find(|p| p.is_dir())
}
