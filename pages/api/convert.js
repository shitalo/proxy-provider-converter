const YAML = require("yaml");
const axios = require("axios");

async function get_proxies(url) {
  let proxies =  undefined;
  try {
    const result = await axios({
      url,
      headers: {
        "User-Agent":
            "ClashX Pro/1.72.0.4 (com.west2online.ClashXPro; build:1.72.0.4; macOS 12.0.1) Alamofire/5.4.4",
      },
    });
    // configFile = result.data
    proxies =YAML.parse(result.data).proxies
  } catch (error) {

  }
  return proxies;
}


module.exports = async (req, res) => {
  const url = req.query.url;
  const target = req.query.target;
  console.log(`query: ${JSON.stringify(req.query)}`);
  if (url === undefined) {
    res.status(400).send("Missing parameter: url");
    return;
  }

  console.log(`Fetching url: ${url}`);
  let configFile = null;
  try {
    const result = await axios({
      url,
      headers: {
        "User-Agent":
          "ClashX Pro/1.72.0.4 (com.west2online.ClashXPro; build:1.72.0.4; macOS 12.0.1) Alamofire/5.4.4",
      },
    });
    configFile = result.data;
  } catch (error) {
    res.status(400).send(`Unable to get url, error: ${error}`);
    return;
  }

  console.log(`Parsing YAML`);
  let config = null;
  try {
    config = YAML.parse(configFile);
    console.log(`👌 Parsed YAML`);
  } catch (error) {
    res.status(500).send(`Unable parse config, error: ${error}`);
    return;
  }

  config.proxies = config.proxies || [];

  try {
    let providers = config['proxy-providers']
    for (const val in providers) {
      // console.log(providers[val]['url'])
      let url = String(providers[val]['url'])
      let proxies = await get_proxies(url)
      if (proxies !== undefined) {
        config.proxies.push(...proxies)
      }
    }
  } catch (error) {
    console.log('获取proxy-providers失败')
  }

  // 剔除不含 type、server、port 内容的节点（无效节点）
  config.proxies = config.proxies.filter(item => item.type && item.server && item.port);
  // 节点去重（根据 type、server、port）
  config.proxies = config.proxies.filter((item, index, self) => {
    const key = `${item.type || ''}-${item.server || ''}-${item.port || ''}`;
    return self.findIndex(i => `${i.type || ''}-${i.server || ''}-${i.port || ''}` === key) === index;
  });

  if (config.proxies === undefined || (Array.isArray(config.proxies) && config.proxies.length === 0)) {
    res.status(400).send("No proxies in this config");
    return;
  }

  if (target === "surge") {
    const supportedProxies = config.proxies.filter((proxy) =>
      ["ss", "vmess", "trojan"].includes(proxy.type)
    );
    const surgeProxies = supportedProxies.map((proxy) => {
      console.log(proxy.server);
      const common = `${proxy.name} = ${proxy.type}, ${proxy.server}, ${proxy.port}`;
      if (proxy.type === "ss") {
        // ProxySS = ss, example.com, 2021, encrypt-method=xchacha20-ietf-poly1305, password=12345, obfs=http, obfs-host=example.com, udp-relay=true
        if (proxy.plugin === "v2ray-plugin") {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge does not support Shadowsocks with v2ray-plugin`
          );
          return;
        }
        let result = `${common}, encrypt-method=${proxy.cipher}, password=${proxy.password}`;
        if (proxy.plugin === "obfs") {
          const mode = proxy?.["plugin-opts"].mode;
          const host = proxy?.["plugin-opts"].host;
          result = `${result}, obfs=${mode}${
            host ? `, obfs-host=example.com ${host}` : ""
          }`;
        }
        if (proxy.udp) {
          result = `${result}, udp-relay=${proxy.udp}`;
        }
        return result;
      } else if (proxy.type === "vmess") {
        // ProxyVmess = vmess, example.com, 2021, username=0233d11c-15a4-47d3-ade3-48ffca0ce119, skip-cert-verify=true, sni=example.com, tls=true, ws=true, ws-path=/path
        if (["h2", "http", "grpc"].includes(proxy.network)) {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge probably doesn't support Vmess(${proxy.network})`
          );
          return;
        }
        let result = `${common}, username=${proxy.uuid}`;
        if (proxy["skip-cert-verify"]) {
          result = `${result}, skip-cert-verify=${proxy["skip-cert-verify"]}`;
        }
        if (proxy.servername) {
          result = `${result}, sni=${proxy.servername}`;
        }
        if (proxy.tls) {
          result = `${result}, tls=${proxy.tls}`;
        }
        if (proxy.network === "ws") {
          result = `${result}, ws=true`;
        }
        if (proxy["ws-path"]) {
          result = `${result}, ws-path=${proxy["ws-path"]}`;
        }
        return result;
      } else if (proxy.type === "trojan") {
        // ProxyTrojan = trojan, example.com, 2021, username=user, password=12345, skip-cert-verify=true, sni=example.com
        if (["grpc"].includes(proxy.network)) {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge probably doesn't support Trojan(${proxy.network})`
          );
          return;
        }
        let result = `${common}, password=${proxy.password}`;
        if (proxy["skip-cert-verify"]) {
          result = `${result}, skip-cert-verify=${proxy["skip-cert-verify"]}`;
        }
        if (proxy.sni) {
          result = `${result}, sni=${proxy.sni}`;
        }
        return result;
      }
    });
    const proxies = surgeProxies.filter((p) => p !== undefined);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(proxies.join("\n"));
  } else {
    const response = YAML.stringify({ proxies: config.proxies });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(response);
  }
};
