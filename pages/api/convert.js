const YAML = require("yaml");
const axios = require("axios");
const Base64 = require("js-base64");
const {ConvertsV2Ray, isBase64, isV2rayLink, urlEncodedCheck} = require("/utils/MihomoParse");
const {proxiesToSub} = require("/utils/SubParse");

async function fetchData(url) {
  console.log(`Fetch url: ${url}`);
  try {
    const result = await axios({
      url,
      headers: {
        "User-Agent": "ClashX Pro/1.72.0.4 (com.west2online.ClashXPro; build:1.72.0.4; macOS 12.0.1) Alamofire/5.4.4",
      },
      timeout: 30 * 1000
    });
    return result;
  } catch (error) {
    console.log(`Fetch url failed: ${url}`);
    return null; // 返回 null 或者一个空字符串，以避免在后续处理中出错
  }
}

function uniqueName(names, name) {
  if (names[name] !== undefined) {
    names[name]++;
    name = `${name}-${String(names[name]).padStart(2, '0')}`;
  } else {
    names[name] = 0;
  }
  return name;
}

function ensureUniqueNames(proxiesArr) {
  let namesCount = {};
  return proxiesArr.map(proxy => {
    const originalName = proxy.name;
    const uniqueNameResult = uniqueName(namesCount, originalName);
    return {
      ...proxy,
      name: uniqueNameResult
    };
  });
}

function subAndProxiesToProxiesArr(data) {
  if (!data) {
    return null;
  }
  try {
    let proxies = YAML.parse(data)['proxies'];
    if (proxies && Array.isArray(proxies)) {
      return proxies;
    }
    if (isV2rayLink(data)) {
      return ConvertsV2Ray(data);
    }
    return null;
  } catch (e) {
    if (isV2rayLink(data)) {
      return ConvertsV2Ray(data);
    }
  }
}

module.exports = async (req, res) => {
  const url = req.query.url;
  const target = req.query.target;
  console.log(`query: ${JSON.stringify(req.query)}`);
  if (url === undefined) {
    res.status(400).send("Missing parameter: url");
    return;
  }

  // 1、http get
  let urlRes = await fetchData(url);

  // 检查响应是否有效
  if (!urlRes) {
    res.status(400).send('Fetching url failed: No response received');
    return;
  }
  if (!urlRes.headers) {
    res.status(400).send('Fetching url failed: No headers in response');
    return;
  }
  if (!urlRes.data) {
    res.status(400).send('Fetching url failed: No data in response');
    return;
  }

  let urlResData = urlRes.data;

  // 设置订阅的流量信息及到期时间
  // let USER_INFO = 'upload=0; download=0; total=2748779069440'
  let USER_INFO = 'upload=268435456000; download=268435456000; total=11534335918080; expire=4102329600';
  if (urlRes.headers['subscription-userinfo']) {
    USER_INFO = urlRes.headers['subscription-userinfo'];
    console.log(USER_INFO)
  }
  res.setHeader('subscription-userinfo', USER_INFO)

  let proxiesArr = []

  // 从proxieos和provider中提取代理
  // 2、proxies解析
  let yml_proxies = subAndProxiesToProxiesArr(urlResData);
  if (yml_proxies && Array.isArray(yml_proxies)) {
    console.log(`proxies中代理数量: ${yml_proxies.length}`)
    proxiesArr.push(...yml_proxies)
  }


  // 3、provider解析
  let fetchPromises = [];

  try {
    let providers = YAML.parse(urlResData)['proxy-providers'];
    for (const val in providers) {
      try {
        let providerUrl = String(providers[val]['url']);
        fetchPromises.push(fetchData(providerUrl)); // 将每个 fetch 请求的 Promise 添加到数组中
      } catch (e) {
        console.error(`Error processing provider: ${e}`);
      }
    }
  } catch (e) {
    console.error(`YAML解析provider失败: ${e}`);
  }

  // 等待所有 fetch 请求完成
  const responses = await Promise.all(fetchPromises);
  // 处理每个响应
  const results = await Promise.all(responses.map(async (response) => {
    try {
      // 检查响应是否有效
      if (!response || !response.headers || !response.data) {
        return null;
      }
      return response.data; // 返回有效的数据
    } catch (e) {
      console.error('Error fetching data from provider:', e);
      return null; // 返回 null 以表示出错
    }
  }));

  for (const val of results) {
    if (val) {
      let provider_proxies = subAndProxiesToProxiesArr(val);
      if (provider_proxies && Array.isArray(provider_proxies)) {
        console.log(`providers中代理数量: ${provider_proxies.length}`);
        proxiesArr.push(...provider_proxies);
      }
    }
  }


  // 剔除不含 type、server、port 内容的节点（无效节点）
  proxiesArr = proxiesArr.filter(item => item.type && item.server && item.port);

  const ssCipher = [
      'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
      'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'aes-128-ccm', 'aes-192-ccm', 'aes-256-ccm',
      'aes-128-gcm-siv', 'aes-256-gcm-siv',
      'chacha20-ietf', 'chacha20', 'xchacha20', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
      'chacha8-ietf-poly1305', 'xchacha8-ietf-poly1305',
      '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
      'lea-128-gcm', 'lea-192-gcm', 'lea-256-gcm',
      'rabbit128-poly1305', 'aegis-128l', 'aegis-256', 'aez-384 ', 'deoxys-ii-256-128', 'rc4-md5', 'none'
  ]

  const vmessCiper = ['auto', 'none', 'zero', 'aes-128-gcm', 'chacha20-poly1305']

  // 节点cipher校验
  proxiesArr = proxiesArr.filter(item => {
    // 滤掉 type 为 'ss' 且 plugin 为 'v2ray-plugin' 的项
    // if (item.type === 'ss' && item.plugin === 'v2ray-plugin') {
    //   return false;
    // }
    if (item.type === 'ss' || item.type === 'ssr') {
      const cipher = ssCipher.includes(item.cipher);
      const plugin = item.plugin === 'v2ray-plugin'

      const flag = cipher && plugin;
      if (!flag) return flag;
    }
    if (item.type === 'vmess') {
      const cipher = vmessCiper.includes(item.cipher);
      const alterId = !isNaN(item.alterId) && isFinite(item.alterId);
      // console.log(item, cipher, alterId);

      const flag = cipher && alterId;
      if (!flag) return flag;
    }

    // 校验 reality-opts.public-key 参数
    if (item['reality-opts'] && item['reality-opts']['public-key']) {
      const pattern = /^[a-zA-Z0-9_-]{43,64}$/;
      const publicKey = item['reality-opts']['public-key'];
      // console.log('public-key参数存在')
      // console.log(item)
      const flag = pattern.test(publicKey);
      // console.log('public-key校验结果：', flag)
      if (!flag) return flag;
    }

    return true;
  });

  // 节点去重（根据 type、server、port）
  proxiesArr = proxiesArr.filter((item, index, self) => {
    const key = `${item.type || ''}-${item.server || ''}-${item.port || ''}`;
    return self.findIndex(i => `${i.type || ''}-${i.server || ''}-${i.port || ''}` === key) === index;
  });

  // 删除ipv6的节点
  proxiesArr = proxiesArr.filter(proxy => !proxy.server.includes(':'));

  // 没有任何节点
  if (!proxiesArr || (Array.isArray(proxiesArr) && proxiesArr.length === 0)) {
    res.status(400).send("No proxies in this config");
    return;
  }

  // 清理 name 字段中的乱码
  proxiesArr = proxiesArr.filter(proxy => {
    // 判断 name 是否包含乱码字符
    if (/[\p{C}]/gu.test(proxy.name)) {
      // 使用正则表达式删除乱码字符
      proxy.name = proxy.name.replace(/[\p{C}]/gu, '');

      // 如果删除乱码后 name 为空，则将 server 的值赋值给 name
      if (!proxy.name) {
        proxy.name = proxy.server;
      }
    }
    return true; // 保留该元素
  });

  // name 去重
  proxiesArr = ensureUniqueNames(proxiesArr);

  if (target === "surge") {
    const supportedProxies = proxiesArr.filter((proxy) =>
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
  } else if (target === "sub") {
    const response = proxiesToSub(proxiesArr);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(response);
  } else {
    let proxiesCount = proxiesArr.length;
    let response = YAML.stringify({ proxies: proxiesArr });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(response);
  }
};
