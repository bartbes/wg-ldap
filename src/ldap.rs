use crate::config::LdapConfig;
use crate::error::Error;
use crate::peer::{PeerParseError, WgPeer};
use ldap3::{LdapConn, SearchEntry};
use std::net::ToSocketAddrs;

struct LdapPeer(SearchEntry);

impl TryInto<WgPeer> for LdapPeer {
    type Error = PeerParseError;

    fn try_into(self) -> Result<WgPeer, Self::Error> {
        let public_key = self
            .0
            .bin_attrs
            .get("wgPublicKey")
            .ok_or(PeerParseError::MissingPublicKey)?
            .iter()
            .next()
            .ok_or(PeerParseError::MissingPublicKey)?
            .as_slice()
            .try_into()?;

        let preshared_key = self
            .0
            .bin_attrs
            .get("wgPresharedKey")
            .and_then(|attrs| attrs.iter().next())
            .map(|attr| attr.as_slice().try_into())
            .map_or(Ok(None), |attr| attr.map(Some))?;

        let allowed_ips = self
            .0
            .attrs
            .get("wgAllowedIp")
            .map(|ips| ips.iter().map(|ip| ip.parse()).collect())
            .unwrap_or(Ok(vec![]))?;

        let endpoint = self
            .0
            .attrs
            .get("wgEndpoint")
            .and_then(|attrs| attrs.iter().next())
            .map(
                |endpoint| match endpoint.to_socket_addrs().map(|mut addrs| addrs.next()) {
                    Ok(Some(addr)) => Ok(addr),
                    Ok(None) => Err(PeerParseError::EndpointDoesNotResolve),
                    Err(err) => Err(err.into()),
                },
            )
            .map_or(Ok(None), |attr| attr.map(Some))?;

        let persistent_keepalive_interval = self
            .0
            .attrs
            .get("wgPersistentKeepalive")
            .and_then(|attrs| attrs.iter().next())
            .map(|attr| attr.parse::<u16>())
            .map_or(Ok(None), |attr| attr.map(Some))?;

        return Ok(WgPeer {
            public_key: public_key,
            preshared_key: preshared_key,
            allowed_ips: allowed_ips,
            endpoint: endpoint,
            persistent_keepalive_interval: persistent_keepalive_interval,
        });
    }
}

pub fn get_peers(conn: &mut LdapConn, config: &LdapConfig) -> Result<Vec<WgPeer>, Error> {
    let search_filter = format!("(&{:}{:})", config.filter, "(objectClass=wgPeer)");
    let (results, _) = conn
        .search(
            &config.base_dn,
            ldap3::Scope::Subtree,
            &search_filter,
            vec!["wgPublicKey", "wgAllowedIp", "wgEndpoint"],
        )?
        .success()?;

    let mut peers: Vec<WgPeer> = vec![];
    for result in results {
        let peer = LdapPeer {
            0: SearchEntry::construct(result),
        };
        peers.push(peer.try_into()?);
    }

    Ok(peers)
}
