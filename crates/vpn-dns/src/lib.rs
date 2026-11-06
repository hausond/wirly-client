//! DNS layer. Phase 0 contains the fake-IP allocator; the actual resolver
//! (hickory-dns, DoH/DoT, split-DNS) lands in phase 2.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// Fake-IP pool over `198.18.0.0/15` (the same range used by Clash/sing-box).
///
/// A client asks the internal DNS for `youtube.com`, gets `198.18.x.y`, and the
/// tunnel maps that address back to the domain when the connection arrives.
#[derive(Debug)]
pub struct FakeIpPool {
    base: u32,
    size: u32,
    next: u32,
    by_domain: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
}

impl Default for FakeIpPool {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeIpPool {
    pub fn new() -> Self {
        // 198.18.0.0/15 -> 131_072 addresses
        Self {
            base: u32::from(Ipv4Addr::new(198, 18, 0, 0)),
            size: 131_072,
            next: 1,
            by_domain: HashMap::new(),
            by_ip: HashMap::new(),
        }
    }

    pub fn is_fake(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 198 && (o[1] == 18 || o[1] == 19)
            }
            IpAddr::V6(_) => false,
        }
    }

    /// Stable allocation: the same domain always gets the same address.
    pub fn allocate(&mut self, domain: &str) -> Ipv4Addr {
        let key = domain.trim_end_matches('.').to_ascii_lowercase();
        if let Some(ip) = self.by_domain.get(&key) {
            return *ip;
        }

        let offset = self.next % self.size;
        self.next = self.next.wrapping_add(1);
        let ip = Ipv4Addr::from(self.base + offset);

        self.by_domain.insert(key.clone(), ip);
        self.by_ip.insert(ip, key);
        ip
    }

    pub fn domain_for(&self, ip: IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V4(v4) => self.by_ip.get(&v4).map(String::as_str),
            IpAddr::V6(_) => None,
        }
    }

    pub fn release(&mut self, domain: &str) -> Option<Ipv4Addr> {
        let key = domain.trim_end_matches('.').to_ascii_lowercase();
        let ip = self.by_domain.remove(&key)?;
        self.by_ip.remove(&ip);
        Some(ip)
    }

    pub fn len(&self) -> usize {
        self.by_domain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_domain.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_stable_addresses() {
        let mut pool = FakeIpPool::new();
        let a = pool.allocate("youtube.com");
        let b = pool.allocate("youtube.com");
        assert_eq!(a, b);
        assert!(FakeIpPool::is_fake(IpAddr::V4(a)));
        assert_eq!(pool.domain_for(IpAddr::V4(a)), Some("youtube.com"));
    }

    #[test]
    fn distinct_domains_get_distinct_ips() {
        let mut pool = FakeIpPool::new();
        let a = pool.allocate("a.example");
        let b = pool.allocate("b.example");
        assert_ne!(a, b);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn release_frees_mapping() {
        let mut pool = FakeIpPool::new();
        let ip = pool.allocate("x.example");
        assert_eq!(pool.release("x.example"), Some(ip));
        assert!(pool.domain_for(IpAddr::V4(ip)).is_none());
        assert!(pool.is_empty());
    }

    #[test]
    fn real_addresses_are_not_fake() {
        assert!(!FakeIpPool::is_fake("8.8.8.8".parse().unwrap()));
        assert!(!FakeIpPool::is_fake("::1".parse().unwrap()));
    }

    #[test]
    fn given_default_pool_then_empty() {
        let pool = FakeIpPool::default();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn given_ipv6_when_looking_up_then_none() {
        let pool = FakeIpPool::new();
        assert!(pool.domain_for("::1".parse().unwrap()).is_none());
    }
}
