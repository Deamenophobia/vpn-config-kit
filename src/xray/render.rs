use super::{
    config::Config,
    state::{Credential, State},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use zeroize::Zeroizing;

pub fn public_key(state: &State) -> Result<String> {
    let raw = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&state.private_key)
            .map_err(|_| anyhow::anyhow!("invalid stored REALITY key"))?,
    );
    ensure!(
        raw.iter().any(|b| *b != 0) && URL_SAFE_NO_PAD.encode(raw.as_slice()) == state.private_key,
        "invalid stored REALITY key"
    );
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid stored REALITY key"))?;
    let key = x25519_dalek::StaticSecret::from(bytes);
    Ok(URL_SAFE_NO_PAD.encode(x25519_dalek::PublicKey::from(&key).as_bytes()))
}
pub fn server(config: &Config, state: &State) -> Result<Zeroizing<String>> {
    config.validate()?;
    let users: Vec<_> = state
        .credentials
        .iter()
        .filter(|p| p.desired())
        .map(|p| json!({"id":p.id,"flow":"xtls-rprx-vision"}))
        .collect();
    let mut short_ids: Vec<_> = state
        .credentials
        .iter()
        .filter(|p| p.desired())
        .map(|p| p.short_id.clone())
        .collect();
    if short_ids.is_empty() {
        short_ids.push(state.instance[..16].to_string());
    }
    let rules = if config.allow_private_destinations {
        vec![]
    } else {
        vec![json!({
            "type":"field","ip":["0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
            "169.254.0.0/16","172.16.0.0/12","192.168.0.0/16","198.18.0.0/15","224.0.0.0/4","240.0.0.0/4","::/0"],
            "outboundTag":"blocked"
        })]
    };
    // The pinned engine also applies outbound final rules after DNS resolution.
    // An explicit allow is required to opt in to private IPv4 destinations.
    let mut final_rules = vec![json!({"action":"block","ip":["::/0"],"blockDelay":"0"})];
    if config.allow_private_destinations {
        final_rules.push(json!({"action":"allow","ip":["0.0.0.0/0"]}));
    }
    Ok(Zeroizing::new(serde_json::to_string_pretty(&json!({
        "log":{"access":"none","error":"none","loglevel":"none"},
        "inbounds":[{
            "tag":"vless-reality","listen":config.listen.to_string(),"port":config.listen_port,
            "protocol":"vless","settings":{"users":users,"decryption":"none"},
            "streamSettings":{"network":"raw","security":"reality","realitySettings":{
                "show":false,"target":config.target,"serverNames":[config.server_name],
                "privateKey":state.private_key,"shortIds":short_ids
            }}
        }],
        "outbounds":[{"tag":"direct","protocol":"freedom","settings":{"finalRules":final_rules},
            "streamSettings":{"sockopt":{"domainStrategy":"ForceIPv4"}}},
            {"tag":"blocked","protocol":"blackhole"}],
        "routing":{"domainStrategy":"IPOnDemand","rules":rules}
    }))?))
}
pub fn client(
    config: &Config,
    state: &State,
    peer: &Credential,
    socks_port: u16,
) -> Result<Zeroizing<String>> {
    ensure!(
        peer.desired() && socks_port != 0,
        "peer is revoked or local SOCKS port is invalid"
    );
    let (host, port) = config
        .endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid endpoint"))?;
    Ok(Zeroizing::new(serde_json::to_string_pretty(&json!({
        "log":{"access":"none","error":"none","loglevel":"none"},
        "inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks",
            "settings":{"auth":"noauth","udp":true}}],
        "outbounds":[{"protocol":"vless","settings":{"vnext":[{
            "address":host,"port":port.parse::<u16>()?,"users":[{
                "id":peer.id,"encryption":"none","flow":"xtls-rprx-vision"
            }]
        }]},"streamSettings":{"network":"raw","security":"reality",
            "realitySettings":{"serverName":config.server_name,"fingerprint":"chrome",
                "password":public_key(state)?,"shortId":peer.short_id},
            "sockopt":{"domainStrategy":"UseIPv4"}
        }}]
    }))?))
}
pub fn link(config: &Config, state: &State, peer: &Credential) -> Result<Zeroizing<String>> {
    ensure!(peer.desired(), "cannot export a revoked credential");
    Ok(Zeroizing::new(format!(
        "vless://{}@{}?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni={}&fp=chrome&pbk={}&sid={}#{}",
        peer.id,
        config.endpoint,
        config.server_name,
        public_key(state)?,
        peer.short_id,
        peer.name
    )))
}
