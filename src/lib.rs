mod common;
mod config;
mod proxy;

use crate::config::Config;
use crate::proxy::*;

use std::collections::HashMap;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde_json::json;
use uuid::Uuid;
use worker::*;
use once_cell::sync::Lazy;
use regex::Regex;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+-\d+$").unwrap());
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z]{2})").unwrap());

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid = env
        .var("UUID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    let main_page_url = env.var("MAIN_PAGE_URL").map(|x| x.to_string()).unwrap();
    let sub_page_url = env.var("SUB_PAGE_URL").map(|x| x.to_string()).unwrap();

    let config = Config {
        uuid,
        host: host.clone(),
        proxy_addr: host,
        proxy_port: 443,
        main_page_url,
        sub_page_url,
    };

    Router::with_data(config)
        .on_async("/", fe)
        .on_async("/sub", sub)
        .on("/link", link)
        .on_async("/:proxyip", tunnel)
        .run(req, env)
        .await
}

async fn get_response_from_url(url: String) -> Result<Response> {
    let req = Fetch::Url(Url::parse(url.as_str())?);
    let mut res = req.send().await?;
    Response::from_html(res.text().await?)
}

async fn fe(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    let host = cx.data.host.to_string();
    let uuid = cx.data.uuid.to_string();

    let vmess_80 = {
        let config = json!({
            "v": "2", "ps": "siren vmess 80", "add": host, "port": "80", "id": uuid,
            "aid": "0", "scy": "zero", "net": "ws", "type": "none", "host": host,
            "path": "/KR", "tls": "", "sni": "", "alpn": ""
        });
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };

    let vmess_443 = {
        let config = json!({
            "v": "2", "ps": "siren vmess 443", "add": host, "port": "443", "id": uuid,
            "aid": "0", "scy": "zero", "net": "ws", "type": "none", "host": host,
            "path": "/KR", "tls": "tls", "sni": host, "alpn": ""
        });
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };

    let vless = format!(
        "vless://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FKR&security=tls&sni={host}#siren vless"
    );
    let trojan = format!(
        "trojan://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FKR&security=tls&sni={host}#siren trojan"
    );
    let ss = format!(
        "ss://{}@{host}:443?plugin=v2ray-plugin%3Btls%3Bmux%3D0%3Bmode%3Dwebsocket%3Bpath%3D%2FKR%3Bhost%3D{host}#siren ss",
        URL_SAFE.encode(format!("none:{uuid}"))
    );

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Siren VPN Configuration</title>
  <style>
    body {
      font-family: 'Arial', sans-serif;
      margin: 0;
      padding: 2rem;
      background-color: #f0f2f5;
      color: #333;
    }

    h1 {
      text-align: center;
      font-size: 2.5rem;
      color: #0056b3;
      margin-bottom: 2rem;
    }

    .config {
      background-color: #fff;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
      border-left: 4px solid #007bff;
      position: relative;
    }

    .config h2 {
      font-size: 1.8rem;
      color: #007bff;
      margin-bottom: 1rem;
    }

    code {
      display: block;
      background-color: #f5f5f5;
      padding: 1rem;
      border-radius: 4px;
      font-size: 1rem;
      white-space: pre-wrap;
      word-wrap: break-word;
    }

    .copy-btn {
      position: absolute;
      top: 1.5rem;
      right: 1.5rem;
      background-color: #007bff;
      color: #fff;
      border: none;
      border-radius: 5px;
      padding: 0.4rem 0.8rem;
      cursor: pointer;
      font-size: 0.9rem;
      transition: background-color 0.3s ease;
    }

    .copy-btn:hover {
      background-color: #0056b3;
    }
  </style>
</head>
<body>
  <h1>Siren VPN Configuration</h1>

  <div class="config">
    <h2>Vmess 80</h2>
    <button class="copy-btn" onclick="copyText('vmess_80')">Copy</button>
    <code id="vmess_80">{vmess_80}</code>
  </div>

  <div class="config">
    <h2>Vmess 443</h2>
    <button class="copy-btn" onclick="copyText('vmess_443')">Copy</button>
    <code id="vmess_443">{vmess_443}</code>
  </div>

  <div class="config">
    <h2>VLESS</h2>
    <button class="copy-btn" onclick="copyText('vless')">Copy</button>
    <code id="vless">{vless}</code>
  </div>

  <div class="config">
    <h2>Trojan</h2>
    <button class="copy-btn" onclick="copyText('trojan')">Copy</button>
    <code id="trojan">{trojan}</code>
  </div>

  <div class="config">
    <h2>Shadowsocks (SS)</h2>
    <button class="copy-btn" onclick="copyText('ss')">Copy</button>
    <code id="ss">{ss}</code>
  </div>

  <script>
    function copyText(id) {
      const codeBlock = document.getElementById(id);
      const text = codeBlock.textContent;
      navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard!');
      }).catch(err => {
        alert('Failed to copy!');
      });
    }
  </script>
</body>
</html>
"#);

    Response::from_html(html)
}

async fn sub(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.sub_page_url).await
}

async fn tunnel(req: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    let mut proxyip = cx.param("proxyip").unwrap().to_string();
    if PROXYKV_PATTERN.is_match(&proxyip) {
        let kvid_list: Vec<String> = proxyip.split(",").map(|s| s.to_string()).collect();
        let kv = cx.kv("SIREN")?;
        let mut proxy_kv_str = kv.get("proxy_kv").text().await?.unwrap_or_default();
        let mut rand_buf = [0u8; 1];
        getrandom::getrandom(&mut rand_buf).expect("failed generating random number");

        if proxy_kv_str.is_empty() {
            console_log!("getting proxy kv from github...");
            let req = Fetch::Url(Url::parse("https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json")?);
            let mut res = req.send().await?;
            if res.status_code() == 200 {
                proxy_kv_str = res.text().await?.to_string();
                kv.put("proxy_kv", &proxy_kv_str)?.expiration_ttl(60 * 60 * 24).execute().await?; // 24 hours
            } else {
                return Err(Error::from(format!("error getting proxy kv: {}", res.status_code())));
            }
        }

        let proxy_kv: HashMap<String, Vec<String>> = serde_json::from_str(&proxy_kv_str)?;

        // select random KV ID
        let kv_index = (rand_buf[0] as usize) % kvid_list.len();
        proxyip = kvid_list[kv_index].clone();

        // select random proxy ip
        let proxyip_index = (rand_buf[0] as usize) % proxy_kv[&proxyip].len();
        proxyip = proxy_kv[&proxyip][proxyip_index].clone().replace(":", "-");
    }

    if PROXYIP_PATTERN.is_match(&proxyip) {
        if let Some((addr, port_str)) = proxyip.split_once('-') {
            if let Ok(port) = port_str.parse() {
                cx.data.proxy_addr = addr.to_string();
                cx.data.proxy_port = port;
            }
        }
    }

    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade == "websocket" {
        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;

        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().unwrap();
            if let Err(e) = ProxyStream::new(cx.data, &server, events).process().await {
                console_log!("[tunnel]: {}", e);
            }
        });

        Response::from_websocket(client)
    } else {
        Response::from_html("hi from wasm!")
    }
}

fn link(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    let host = cx.data.host.to_string();
    let uuid = cx.data.uuid.to_string();

    let vmess_80 = {
        let config = json!({
            "v": "2", "ps": "siren vmess 80", "add": host, "port": "80", "id": uuid,
            "aid": "0", "scy": "zero", "net": "ws", "type": "none", "host": host,
            "path": "/KR", "tls": "", "sni": "", "alpn": ""
        });
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };

    let vmess_443 = {
        let config = json!({
            "v": "2", "ps": "siren vmess 443", "add": host, "port": "443", "id": uuid,
            "aid": "0", "scy": "zero", "net": "ws", "type": "none", "host": host,
            "path": "/KR", "tls": "tls", "sni": host, "alpn": ""
        });
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };

    let vless = format!(
        "vless://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FKR&security=tls&sni={host}#siren vless"
    );
    let trojan = format!(
        "trojan://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FKR&security=tls&sni={host}#siren trojan"
    );
    let ss = format!(
        "ss://{}@{host}:443?plugin=v2ray-plugin%3Btls%3Bmux%3D0%3Bmode%3Dwebsocket%3Bpath%3D%2FKR%3Bhost%3D{host}#siren ss",
        URL_SAFE.encode(format!("none:{uuid}"))
    );

    Response::from_body(ResponseBody::Body(
        format!("{vmess_80}\n{vmess_443}\n{vless}\n{trojan}\n{ss}").into(),
    ))
}
