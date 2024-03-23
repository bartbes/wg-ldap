mod config;
mod error;
mod ldap;
mod peer;

use crate::config::{Config, LdapAuthConfig, LdapConfig};
use crate::error::Error;
use crate::ldap::get_peers;
use crate::peer::WgPeer;
use ldap3::{LdapConn, LdapConnSettings};
use wireguard_uapi::{DeviceInterface, WgSocket};
use base64::engine::Engine;

#[derive(Debug, Default)]
struct ClassifiedPeers<'a> {
    pub this_peer: Option<WgPeer>,
    pub new_peers: Vec<WgPeer>,
    pub matched_peers: Vec<WgPeer>,
    pub missing_peers: Vec<&'a wireguard_uapi::get::Peer>,
}

fn classify<'a>(
    device: &'a wireguard_uapi::get::Device,
    peers: Vec<WgPeer>,
) -> ClassifiedPeers<'a> {
    let mut results = ClassifiedPeers::default();

    for peer in &device.peers {
        if !peers
            .iter()
            .any(|candidate| candidate.public_key == peer.public_key)
        {
            results.missing_peers.push(peer);
        }
    }

    for peer in peers {
        if device.public_key == Some(peer.public_key) {
            results.this_peer = Some(peer);
        } else if device
            .peers
            .iter()
            .any(|candidate| candidate.public_key == peer.public_key)
        {
            results.matched_peers.push(peer);
        } else {
            results.new_peers.push(peer);
        }
    }

    results
}

fn connect_to_ldap(config: &LdapConfig) -> Result<LdapConn, Box<dyn std::error::Error>> {
    let mut conn_settings = LdapConnSettings::new().set_starttls(config.start_tls);

    if let Some(ca_path) = &config.root_certificate {
        let mut tls_builder = native_tls::TlsConnector::builder();
        let pem = std::fs::read_to_string(ca_path)?;
        let ca = native_tls::Certificate::from_pem(pem.as_bytes())?;
        tls_builder.add_root_certificate(ca);
        tls_builder.disable_built_in_roots(true);
        conn_settings = conn_settings.set_connector(tls_builder.build()?);
    }

    let mut ldap_conn = LdapConn::with_settings(conn_settings, config.url.as_str())?;
    match &config.auth {
        LdapAuthConfig::None => (),
        LdapAuthConfig::SimpleBind(bind) => {
            ldap_conn.simple_bind(&bind.bind_dn, &bind.bind_pw)?;
        }
        LdapAuthConfig::GSSAPI(bind) => {
            let fqdn = match bind.ignore_acceptor_hostname {
                true => config
                    .url
                    .host_str()
                    .map_or(Err(Error::InvalidLdapUrl), |host| Ok(host))?,
                false => unimplemented!(),
            };
            ldap_conn.sasl_gssapi_bind(fqdn)?;
        }
    }

    Ok(ldap_conn)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = std::env::args().nth(1).unwrap_or("config.toml".into());
    let config = std::fs::read_to_string(config)?;
    let config: Config = toml::from_str(&config)?;

    let mut ldap_conn = connect_to_ldap(&config.ldap)?;
    let mut wg = WgSocket::connect()?;
    let interface = DeviceInterface::from_name(&config.wireguard.device_name);
    let get_device = wg.get_device(interface)?;
    let b64 = base64::engine::general_purpose::STANDARD;

    let peers = get_peers(&mut ldap_conn, &config.ldap)?;
    let peers = classify(&get_device, peers);

    if let Some(peer) = &peers.this_peer {
        println!("Found self, with endpoint {:?}", peer.endpoint);
    }

    let mut update_interface = false;
    let mut new_peer_list = vec![];
    for peer in &peers.new_peers {
        println!(
            "Found new peer with public key {}",
            b64.encode(&peer.public_key)
        );
        new_peer_list.push(peer.into());
        update_interface = true;
    }

    for peer in &peers.matched_peers {
        println!(
            "Found existing peer with public key {}",
            b64.encode(&peer.public_key)
        );
        new_peer_list.push(peer.into());
    }

    for peer in &peers.missing_peers {
        println!(
            "Missing peer with public key {}",
            b64.encode(&peer.public_key)
        );
    }

    let mut flags = vec![];
    if config.wireguard.remove_extra_peers && !peers.missing_peers.is_empty() {
        flags.push(wireguard_uapi::linux::set::WgDeviceF::ReplacePeers);
        update_interface = true;
    }

    let mut listen_port = config.wireguard.listen_port;
    if config.wireguard.match_listen_port_to_local_endpoint {
        if let Some(peer) = &peers.this_peer {
            if let Some(endpoint) = peer.endpoint {
                listen_port = Some(endpoint.port());
            }
        }
    }

    if listen_port.map_or(false, |port| port != get_device.listen_port) {
        update_interface = true;
    }

    if update_interface {
        let set_device = wireguard_uapi::linux::set::Device {
            interface: wireguard_uapi::linux::DeviceInterface::from_index(get_device.ifindex),
            flags: flags,
            private_key: None,
            listen_port: listen_port,
            fwmark: None,
            peers: new_peer_list,
        };
        wg.set_device(set_device)?;
    }

    Ok(())
}
