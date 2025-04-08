# Siren

an Indonesia serverless v2ray tunnel

## Features

- [x] Protocol support:
  - [x] Vmess
  - [x] Trojan
  - [x] VLESS
  - [x] Shadowsocks
- [x] Domain over https

## Endpoints

- / > Main page
- /link > Proxy link
- /sub > Subscription page

## Deploy

### CI (Github Actions)

1. [Create an API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) from the cloudflare dashboard.
2. Create a `Repository Secret` called `CLOUDFLARE_API_TOKEN` and paste API Token from the first steps.
3. Open `Actions` tab and enable workflows
4. Push a commit or run the workflow manually
5. Access `https://YOUR-WORKERS-SUBDOMAIN.workers.dev`
