use serde::Deserialize;
use url::Url;

#[derive(Deserialize, Debug)]
pub struct LdapSimpleBind {
    pub bind_dn: String,
    pub bind_pw: String,
}

#[derive(Deserialize, Debug)]
pub struct LdapSaslBindGssapi {
    #[serde(default)]
    pub ignore_acceptor_hostname: bool,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum LdapAuthConfig {
    None,
    SimpleBind(LdapSimpleBind),
    GSSAPI(LdapSaslBindGssapi),
}

impl Default for LdapAuthConfig {
    fn default() -> Self {
        LdapAuthConfig::None
    }
}

#[derive(Deserialize, Debug)]
pub struct LdapConfig {
    pub url: Url,

    #[serde(default)]
    pub start_tls: bool,

    pub root_certificate: Option<String>,

    pub base_dn: String,

    #[serde(default)]
    pub auth: LdapAuthConfig,

    #[serde(default)]
    pub filter: String,
}

#[derive(Deserialize, Debug)]
pub struct WgConfig {
    pub device_name: String,

    pub listen_port: Option<u16>,

    #[serde(default)]
    pub match_listen_port_to_local_endpoint: bool,

    pub remove_extra_peers: bool,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    pub ldap: LdapConfig,
    pub wireguard: WgConfig,
}
