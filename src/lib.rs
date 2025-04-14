mod common;
mod config;
mod proxy;

use crate::config::Config;
use crate::proxy::*;
use worker::*;
use serde_json::json;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid = env
        .var("UUID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    let main_page_url = env.var("MAIN_PAGE_URL").map(|x| x.to_string()).unwrap();
    let sub_page_url = env.var("SUB_PAGE_URL").map(|x|x.to_string()).unwrap();
    let config = Config { uuid, host: host.clone(), proxy_addr: host, proxy_port: 443, main_page_url, sub_page_url};

    Router::with_data(config)
        .on_async("/", fe)
        .on_async("/sub", sub)
        .on("/link", link)
        .run(req, env)
        .await
}

// Generate HTML with proper values
async fn link(req: Request, cx: RouteContext<Config>) -> Result<Response> {
    let host = cx.data.host.to_string();
    let uuid = cx.data.uuid.to_string();

    // Vmess configuration for port 80 and 443
    let vmess_80 = format!("vmess://{}", URL_SAFE.encode(json!({
        "ps": "siren vmess 80",
        "v": "2",
        "add": host,
        "port": "80",
        "id": uuid,
        "aid": "0",
        "scy": "zero",
        "net": "ws",
        "type": "none",
        "host": host,
        "path": "/KR",
        "tls": "zero",
        "sni": "",
        "alpn": ""
    }).to_string()));

    let vmess_443 = format!("vmess://{}", URL_SAFE.encode(json!({
        "ps": "siren vmess 443",
        "v": "2",
        "add": host,
        "port": "443",
        "id": uuid,
        "aid": "0",
        "scy": "zero",
        "net": "ws",
        "type": "none",
        "host": host,
        "path": "/KR",
        "tls": "zero",
        "sni": "",
        "alpn": ""
    }).to_string()));

    // Vless, Trojan, and Shadowsocks (SS)
    let vless_link = format!("vless://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FKR&security=tls&sni={host}#siren vless");
    let trojan_link = format!("trojan://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FKR&security=tls&sni={host}#siren trojan");
    let ss_link = format!("ss://{}@{host}:443?plugin=v2ray-plugin%3Btls%3Bmux%3D0%3Bmode%3Dwebsocket%3Bpath%3D%2FKR%3Bhost%3D{host}#siren ss", URL_SAFE.encode(format!("none:{uuid}")));

    // Build HTML response with configuration
    let html_content = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
            <title>Siren VPN Configuration</title>
            <style>
                body {{
                    font-family: "Segoe UI", sans-serif;
                    background: #f2f6fc;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 800px;
                    margin: auto;
                    background: #fff;
                    padding: 30px;
                    border-radius: 16px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                }}
                h1 {{
                    text-align: center;
                    color: #4a90e2;
                    margin-bottom: 30px;
                }}
                .section {{
                    margin-bottom: 25px;
                }}
                .section h2 {{
                    color: #333;
                    font-size: 20px;
                    margin-bottom: 10px;
                }}
                .config-box {{
                    display: flex;
                    align-items: center;
                    background: #f5f7fa;
                    border-radius: 10px;
                    padding: 10px 15px;
                    box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.05);
                    margin-bottom: 10px;
                }}
                .config-box input {{
                    flex: 1;
                    border: none;
                    background: transparent;
                    font-size: 14px;
                    color: #333;
                    padding: 8px;
                    outline: none;
                }}
                .copy-btn {{
                    background: #4a90e2;
                    color: #fff;
                    border: none;
                    padding: 8px 12px;
                    border-radius: 8px;
                    cursor: pointer;
                    transition: background 0.3s;
                }}
                .copy-btn:hover {{
                    background: #357ab8;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 40px;
                    color: #888;
                    font-size: 13px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Siren VPN Configuration</h1>

                <div class="section">
                    <h2>Vmess 80</h2>
                    <div class="config-box">
                        <input type="text" id="vmess_80" value="{vmess_80}" readonly>
                        <button class="copy-btn" onclick="copyToClipboard('vmess_80')">Copy</button>
                    </div>
                </div>

                <div class="section">
                    <h2>Vmess 443</h2>
                    <div class="config-box">
                        <input type="text" id="vmess_443" value="{vmess_443}" readonly>
                        <button class="copy-btn" onclick="copyToClipboard('vmess_443')">Copy</button>
                    </div>
                </div>

                <div class="section">
                    <h2>VLESS</h2>
                    <div class="config-box">
                        <input type="text" id="vless" value="{vless_link}" readonly>
                        <button class="copy-btn" onclick="copyToClipboard('vless')">Copy</button>
                    </div>
                </div>

                <div class="section">
                    <h2>Trojan</h2>
                    <div class="config-box">
                        <input type="text" id="trojan" value="{trojan_link}" readonly>
                        <button class="copy-btn" onclick="copyToClipboard('trojan')">Copy</button>
                    </div>
                </div>

                <div class="section">
                    <h2>Shadowsocks (SS)</h2>
                    <div class="config-box">
                        <input type="text" id="ss" value="{ss_link}" readonly>
                        <button class="copy-btn" onclick="copyToClipboard('ss')">Copy</button>
                    </div>
                </div>

                <div class="footer">
                    &copy; 2025 Siren VPN — All rights reserved
                </div>
            </div>

            <script>
                function copyToClipboard(id) {{
                    const input = document.getElementById(id);
                    input.select();
                    input.setSelectionRange(0, 99999); // For mobile
                    document.execCommand("copy");
                    alert("Copied!");
                }}
            </script>
        </body>
        </html>
        "#,
        vmess_80 = vmess_80,
        vmess_443 = vmess_443,
        vless_link = vless_link,
        trojan_link = trojan_link,
        ss_link = ss_link
    );

    Response::from_html(html_content)
}
