use std::net::SocketAddr;
use thiserror::Error;
use wireguard_uapi::get::{AllowedIp, ParseAllowedIpError};

#[derive(Error, Debug)]
pub enum PeerParseError {
    #[error("No wgPublicKey found on wgPeer")]
    MissingPublicKey,

    #[error("Specified wgPublicKey or wgPresharedKey key is wrong length")]
    InvalidKey(#[from] std::array::TryFromSliceError),

    #[error("Cannot parse wgAllowedIp")]
    InvalidAllowedIp(#[from] ParseAllowedIpError),

    #[error("Cannot parse wgEndpoint")]
    InvalidEndpoint(#[from] std::io::Error),

    #[error("Cannot resolve wgEndpoint to address")]
    EndpointDoesNotResolve,

    #[error("Cannot parse wgPersistentKeepalive")]
    InvalidPersistentKeepalive(#[from] std::num::ParseIntError),
}

#[derive(Debug)]
pub struct WgPeer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<AllowedIp>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: Option<u16>,
}

impl<'a> Into<wireguard_uapi::linux::set::Peer<'a>> for &'a WgPeer {
    fn into(self) -> wireguard_uapi::linux::set::Peer<'a> {
        let set_allowed_ips = self
            .allowed_ips
            .iter()
            .map(|get_ip| wireguard_uapi::linux::set::AllowedIp {
                ipaddr: &get_ip.ipaddr,
                cidr_mask: Some(get_ip.cidr_mask),
            })
            .collect();
        return wireguard_uapi::linux::set::Peer::<'a> {
            public_key: &self.public_key,
            flags: vec![],
            preshared_key: self.preshared_key.as_ref(),
            endpoint: self.endpoint.as_ref(),
            persistent_keepalive_interval: self.persistent_keepalive_interval,
            allowed_ips: set_allowed_ips,
            protocol_version: None,
        };
    }
}
