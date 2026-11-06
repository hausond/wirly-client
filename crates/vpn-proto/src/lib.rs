//! Protocol layer.
//!
//! Every protocol is an [`Outbound`]: it turns a destination into a stream (TCP)
//! or a datagram socket (UDP). The tunnel core does not care which protocol is used.
//!
//! Phase 1 implementations: WireGuard (`boringtun`), Shadowsocks-2022
//! (`shadowsocks-rust`), Trojan, VLESS over WS/TLS.
//! Phase 3: VLESS + REALITY on top of BoringSSL.

mod outbound;
mod stubs;

pub use outbound::{create, Outbound, ProtoError, Target};
