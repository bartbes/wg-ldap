use crate::peer::PeerParseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not parse wgPeer")]
    PeerParseError(#[from] PeerParseError),

    #[error("Error fetching data from directory server")]
    LdapError(#[from] ldap3::LdapError),

    #[error("Invalid ldap url specified")]
    InvalidLdapUrl,
}
