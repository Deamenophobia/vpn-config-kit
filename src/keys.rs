use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct Secret(pub(crate) Zeroizing<String>);
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
impl Secret {
    pub fn parse(value: String) -> Result<Self> {
        let value = Zeroizing::new(value);
        decode(value.trim())?;
        Ok(Self(Zeroizing::new(value.trim().to_owned())))
    }
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        Self(Zeroizing::new(STANDARD.encode(secret.to_bytes())))
    }
    pub fn public_key(&self) -> Result<String> {
        let bytes = Zeroizing::new(decode(&self.0)?);
        let key = StaticSecret::from(*bytes);
        Ok(STANDARD.encode(PublicKey::from(&key).as_bytes()))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
pub fn decode(value: &str) -> Result<[u8; 32]> {
    let bytes = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|_| anyhow::anyhow!("invalid WireGuard key encoding"))?,
    );
    ensure!(
        bytes.len() == 32 && bytes.iter().any(|b| *b != 0),
        "invalid WireGuard key length or zero key"
    );
    ensure!(
        STANDARD.encode(&*bytes) == value,
        "noncanonical WireGuard key"
    );
    Ok(bytes.as_slice().try_into().expect("checked key length"))
}
