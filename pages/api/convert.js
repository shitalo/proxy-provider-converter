const YAML = require("yaml");
const axios = require("axios");
const Base64 = require("js-base64");
const {ConvertsV2Ray, isBase64, isV2rayLink, urlEncodedCheck} = require("../../utils/MihomoParse");

function parse_hysteria(outbounds_n) {
  let name = findFieldValue(outbounds_n, "name") || "";
  let server = findFieldValue(outbounds_n, "server") || "";
  if (server.startsWith("127.0.0.1") || server === "") {
    return "";
  }
  let port = findFieldValue(outbounds_n, "server_port") || findFieldValue(outbounds_n, 'port');

  let upmbps_str = findFieldValue(outbounds_n, "up_mbps") || findFieldValue(outbounds_n, 'up');
  let downmbps_str = findFieldValue(outbounds_n, "down_mbps") || findFieldValue(outbounds_n, 'down');

  // 提取字符串中的数字，然后转换为数字类型
  let upmbps = parseInt(String(upmbps_str).replace(/\D/g, ''), 10) || 0;
  let downmbps = parseInt(String(downmbps_str).replace(/\D/g, ''), 10) || 0;

  let auth = findFieldValue(outbounds_n, "auth_str") || findFieldValue(outbounds_n, 'auth-str');
  let peer = findFieldValue(outbounds_n, "server_name") || findFieldValue(outbounds_n, 'sni') || "";

  let protocolValue = findFieldValue(outbounds_n, 'protocol');
  let protocol = protocolValue !== "hysteria" ? protocolValue : ""

  let insecureFieldValue = findFieldValue(outbounds_n, "insecure");
  let insecure = [null, true].includes(insecureFieldValue) ? 1 : "";

  let alpnValue = findFieldValue(outbounds_n, "alpn");
  let alpn;
  if (typeof alpnValue === "string") {
    alpn = alpnValue;
  } else {
    alpn = alpnValue.length === 1 ? alpnValue[0].toString() : alpnValue.join(',');
  }

  let hysteriaDict = {
    "upmbps": upmbps,
    "downmbps": downmbps,
    "auth": auth,
    "protocol": protocol,
    "insecure": insecure,
    "peer": peer,
    "alpn": alpn,
  }
  // 过滤掉值为空的键值对
  const filteredParams = Object.fromEntries(
      Object.entries(hysteriaDict).filter(([key, value]) => value !== '' && value !== null && value !== undefined)
  );
  // 进行 URL 参数编码
  const encodedParams = new URLSearchParams(filteredParams).toString();
  // 拼接链接
  let hy1 = `hysteria://${server}:${port}?${encodedParams}#[hysteria]_${server}:${port}`;

  return hy1;
}

// ------------------------------------------ 解析和构建 hy2 节点 -------------------------------------------

function parse_hy2(outbounds_n) {
  let name = findFieldValue(outbounds_n, "name") || "";
  let server = findFieldValue(outbounds_n, 'server') || "";
  if (server.startsWith("127.0.0.1") || server === "") {
    return "";
  }
  let port = findFieldValue(outbounds_n, 'port');

  // 排除"domain:port"、"ipv4:port" 或 "ipv6:port" 这三种情况地址的正则表达式
  let genericAddressRegex = /^(?!.*:\d+$)(?!\[.*\].*:\d+$)/
  if (genericAddressRegex.test(server)) {
    server = `${server}:${port}`;
  }

  let password = findFieldValue(outbounds_n, 'password') || findFieldValue(outbounds_n, 'auth');
  let obfs = findFieldValue(outbounds_n, 'obfs') || "";
  let obfs_password = findFieldValue(outbounds_n, 'obfs-password') || "";
  let sni = findFieldValue(outbounds_n, 'sni') || "";

  let up = findFieldValue(outbounds_n, 'up') || "80";
  let down = findFieldValue(outbounds_n, 'down') || "100";
  // 提取字符串中的数字，然后转换为数字类型
  let upmbps = parseInt(String(up).replace(/\D/g, ''), 10) || 0;
  let downmbps = parseInt(String(down).replace(/\D/g, ''), 10) || 0;

  let insecureFieldValue = findFieldValue(outbounds_n, "insecure");
  let insecure = [null, true].includes(insecureFieldValue) ? 1 : "";

  let hy2Dict = {
    "upmbps": upmbps,
    "downmbps": downmbps,
    "obfs": obfs,
    "obfs-password": obfs_password,
    "sni": sni,
    "insecure": insecure
  }

  // 过滤掉值为空的键值对
  const filteredParams = Object.fromEntries(
      Object.entries(hy2Dict).filter(([key, value]) => value !== '' && value !== null && value !== undefined)
  );
  // 进行 URL 参数编码
  const encodedParams = new URLSearchParams(filteredParams).toString();

  let hy2 = `hy2://${password}@${server}?${encodedParams}#[hy2]_${server}`;

  return hy2;
}

// ----------------------------------------- 解析和构建 vless 节点 ------------------------------------------

function parse_vless(outbounds_n) {
  let name = findFieldValue(outbounds_n, "name") || "";
  let address = findFieldValue(outbounds_n, "address") || findFieldValue(outbounds_n, 'server') || "";
  if (address === "127.0.0.1" || address === "") {
    return "";
  }
  let port = findFieldValue(outbounds_n, "port");
  let uuid = findFieldValue(outbounds_n, "id") || findFieldValue(outbounds_n, 'uuid');
  let encryption = findFieldValue(outbounds_n, "encryption") || "none"; // 加密方式
  let flow = findFieldValue(outbounds_n, 'flow') || "";
  let network = findFieldValue(outbounds_n, "network");
  let host = findFieldValue(outbounds_n, "Host") || findFieldValue(outbounds_n, 'host') || "";
  let path = findFieldValue(outbounds_n, "path") || "";
  // 目前发现publicKey和shortId是reality独有
  let public_key = findFieldValue(outbounds_n, 'public-key') || findFieldValue(outbounds_n, 'publicKey') || "";
  let short_id = findFieldValue(outbounds_n, 'short-id') || findFieldValue(outbounds_n, 'shortId') || "";
  // sni
  let serverName = findFieldValue(outbounds_n, "serverName") || findFieldValue(outbounds_n, 'servername') || "";
  if (host === "" && serverName === "") {
    host = address
  } else if (host === "" && serverName !== "") {
    host = serverName
  }
  // 传输层安全(TLS)
  let tls_security;
  if (public_key !== "") {
    tls_security = "reality";
  } else {
    let tls = findFieldValue(outbounds_n.streamSettings, 'security') || findFieldValue(outbounds_n, 'tls') || "";
    if (tls === "none") {
      tls_security = "";
    } else if (tls === true) {
      tls_security = "tls";
    } else {
      tls_security = "";
    }
  }
  if (tls_security === "" && network === "ws" && serverName !== "") {
    tls_security = "tls";
  }
  let fp = findFieldValue(outbounds_n, "fingerprint") || findFieldValue(outbounds_n, 'client-fingerprint') || "";
  let vlessDict = {
    "encryption": encryption, // 加密方式
    "flow": flow,
    "security": tls_security, // 传输层安全(TLS)
    "sni": serverName,
    "fp": fp,
    "pbk": public_key,
    "sid": short_id,
    "type": network, // 传输协议(network)
    "host": host, // 伪装域名(host)
    "path": path,
    "headerType": "" // 伪装类型(type)
  }

  // 过滤掉值为空的键值对
  const filteredParams = Object.fromEntries(
      Object.entries(vlessDict).filter(([key, value]) => value !== '' && value !== null && value !== undefined)
  );
  // 进行 URL 参数编码
  const encodedParams = new URLSearchParams(filteredParams).toString();

  // let vless = `vless://${uuid}@${address}:${port}?${encodedParams}#[vless]_${address}:${port}`;
  let vless = `vless://${uuid}@${address}:${port}?${encodedParams}#${name}`;

  return vless;
}

// ----------------------------------------- 解析和构建 vmess 节点 ------------------------------------------

function parse_vmess(outbounds_n) {
  let name = findFieldValue(outbounds_n, "name") || "";
  let address = findFieldValue(outbounds_n, "address") || findFieldValue(outbounds_n, 'server') || "";
  if (address === "127.0.0.1" || address === "") {
    return "";
  }
  let port = findFieldValue(outbounds_n, 'port');
  let uuid = findFieldValue(outbounds_n, 'id') || findFieldValue(outbounds_n, 'uuid');
  let alterId = findFieldValue(outbounds_n, 'alterId') || 0;

  // 加密方式(security)
  let auto_security = findFieldValue(outbounds_n, 'cipher') || findFieldValue(outbounds_n.settings, 'security') || "auto";

  // 传输协议(network)
  let network = findFieldValue(outbounds_n, 'network');
  // 伪装类型(type)
  let type_encryption = findFieldValue(outbounds_n, 'encryption') || "none";

  // 传输层安全(TLS)
  let tls = findFieldValue(outbounds_n.streamSettings, 'security') || findFieldValue(outbounds_n, 'tls') || "";
  let tls_security = tls === true ? 'tls' || "" : tls

  let path = findFieldValue(outbounds_n, 'path') || findFieldValue(outbounds_n, 'ws-path') || findFieldValue(outbounds_n, 'grpc-service-name') || "/";
  // 伪装域名(host)
  let host = findFieldValue(outbounds_n, 'Host') || findFieldValue(outbounds_n, 'host') || "";
  let serverName = findFieldValue(outbounds_n, 'sni') || findFieldValue(outbounds_n, 'serverName') || "";
  if (serverName === "" && host === "") {
    host = address;
  }
  let fp = findFieldValue(outbounds_n, 'client-fingerprint') || findFieldValue(outbounds_n, 'fingerprint') || "";
  let vmess_dict = {
    "v": "2",
    // "ps": `[vmess]_${address}:${port}`,
    "ps": `${name}`,
    "add": address,
    "port": port,
    "id": uuid,
    "aid": alterId, // 额外ID(alterId)
    "scy": auto_security, // 加密方式(security)
    "net": network, // 传输协议(network)
    "type": type_encryption, // 伪装类型(type)
    "host": host, // 伪装域名(host)
    "path": path, // 路径
    "tls": tls_security, // 传输层安全(TLS)
    "sni": serverName,
    "alpn": "",
    "fp": fp
  }
  // 将对象转换为 JSON 字符串（方便后面进行base64编码）
  const jsonString = JSON.stringify(vmess_dict);

  /*
      由于btoa主要用于处理 Latin-1 字符串，如果字符串包含非 Latin-1 字符（比如 Unicode 字符），
      要编码成Base64字符串，就使用 TextEncoder 和 Uint8Array。
  */
  const encoder = new TextEncoder();
  const uint8Array = encoder.encode(jsonString);
  const base64EncodedString = btoa(String.fromCharCode.apply(null, uint8Array));
  const vmess = `vmess://${base64EncodedString}`;

  return vmess;
}

// -------------------------------------- 解析和构建 shadowsocks 节点 ---------------------------------------

function parse_shadowsocks(outbounds_n) {
  let name = (findFieldValue(outbounds_n, 'name') || `[ss]_${address}`).trim();

  let address = findFieldValue(outbounds_n, 'address') || findFieldValue(outbounds_n, 'server') || "";
  if (address === "127.0.0.1" || address === "") {
    return "";
  }

  let port = findFieldValue(outbounds_n, 'port');
  let method = findFieldValue(outbounds_n, 'method') || findFieldValue(outbounds_n, 'cipher');
  let password = findFieldValue(outbounds_n, 'password');
  let method_with_password = `${method}:${password}`;
  let base64EncodedString = utf8ToBase64(method_with_password);
  // let ss = `ss://${base64EncodedString}@${address}:${port}#[ss]_${address}`;
  let ss = `ss://${base64EncodedString}@${address}:${port}#${name}`;

  return ss;
}

// ----------------------------------------- 解析和构建 trojan 节点 -----------------------------------------

function parse_trojan(outbounds_n) {
  let name = findFieldValue(outbounds_n, "name") || "";
  let server = findFieldValue(outbounds_n, "server") || "";
  if (server.startsWith("127.0.0.1") || server === "") {
    return "";
  }
  let port = findFieldValue(outbounds_n, 'port');
  let password = findFieldValue(outbounds_n, 'password');
  let network = findFieldValue(outbounds_n, 'network') || "tcp";
  let path = findFieldValue(outbounds_n, 'path') || "";
  let host = findFieldValue(outbounds_n, 'Host') || findFieldValue(outbounds_n, 'host') || "";
  let sni = findFieldValue(outbounds_n, 'sni') || "";
  let fp = findFieldValue(outbounds_n, 'client-fingerprint') || findFieldValue(outbounds_n, 'fingerprint') || "";
  let alpn = findFieldValue(outbounds_n, 'alpn') || ""; // 没有确定字段是否这个名字
  let tls_security = "";
  if (sni) {
    tls_security = "tls";
  }

  let trojanDict = {
    "security": tls_security,
    "allowInsecure": 1,
    "sni": sni,
    "fp": fp,
    "type": network,
    "host": host,
    "alpn": alpn,
    "path": path
  }

  // 过滤掉值为空的键值对
  const filteredParams = Object.fromEntries(
      Object.entries(trojanDict).filter(([key, value]) => value !== '' && value !== null && value !== undefined)
  );
  // 进行 URL 参数编码
  const encodedParams = new URLSearchParams(filteredParams).toString();

  // let trojan = `trojan://${password}@${server}:${port}?${encodedParams}#[trojan]_${server}`;
  let trojan = `trojan://${password}@${server}:${port}?${encodedParams}#${name}`;

  return trojan;
}

// ------------------------------------------ 解析和构建 tuic 节点 ------------------------------------------

function parse_tuic(outbounds_n) {
  let name = findFieldValue(outbounds_n, "name") || "";
  let uuid = findFieldValue(outbounds_n, 'uuid');
  let password = findFieldValue(outbounds_n, 'password');
  let server = findFieldValue(outbounds_n, 'server') || "";
  if (server === "127.0.0.1" || server === "") {
    return "";
  }
  let port = findFieldValue(outbounds_n, 'port');
  let congestion_controller = findFieldValue(outbounds_n, 'congestion-controller');
  let udp_relay_mode = findFieldValue(outbounds_n, 'udp-relay-mode');
  let sni = findFieldValue(outbounds_n, 'sni') || "";
  let alpnValue = findFieldValue(outbounds_n, "alpn");
  var alpn;
  if (alpnValue.length === 1) {
    // 如果数组只有一个元素，直接获取该元素
    alpn = alpnValue[0].toString();
  } else {
    // 如果数组有多个元素，使用逗号连接
    alpn = alpnValue.join(',');
  }
  let tuicDict = {
    "congestion_control": congestion_controller,
    "udp_relay_mode": udp_relay_mode,
    "alpn": alpn,
    "sni": sni,
    "allow_insecure": 1
  }
  // 过滤掉值为空的键值对
  const filteredParams = Object.fromEntries(
      Object.entries(tuicDict).filter(([key, value]) => value !== '' && value !== null && value !== undefined)
  );
  // 进行 URL 参数编码
  const encodedParams = new URLSearchParams(filteredParams).toString();
  let tuic = `tuic://${uuid}:${password}@${server}:${port}?${encodedParams}#[tuic]_${server}`;

  return tuic;
}

// ------------------------------------------- 递归查找字段对应的值 ------------------------------------------

function findFieldValue(obj, targetField) {
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      if (key === targetField) {
        return obj[key];
      } else if (typeof obj[key] === 'object') {
        const result = findFieldValue(obj[key], targetField);
        if (result != undefined) {
          return result;
        }
      }
    }
  }
  return null; // 如果未找到字段，返回null
}

function utf8ToBase64(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const res = Base64.encode(String.fromCharCode(...new Uint8Array(data)));
  return res;
}

function proxiesToSub(outbounds) {
  const uniqueSet = new Set();
  let allProxyType = ["hysteria", "hysteria1", "hy1", "hysteria2", "hy2", "vless", "vmess", "trojan", "ss", "shadowsocks", "tuic"]

  // 遍历数组中的节点
  for (var i = 0; i < outbounds.length; i++) {
    let proxyType = findFieldValue(outbounds[i], "protocol");
    if (!allProxyType.includes(proxyType)) {
      proxyType = findFieldValue(outbounds[i], "type")
    }
    // 检查到是hysteria类型的节点
    if (["hysteria", "hysteria1", "hy1"].includes(proxyType)) {
      let hy1 = parse_hysteria(outbounds[i]);
      if (hy1) {
        uniqueSet.add(hy1);
      }
      // 检查到是hy2类型的节点
    } else if (["hy2", "hysteria2"].includes(proxyType)) {
      let hy2 = parse_hy2(outbounds[i]);
      if (hy2) {
        uniqueSet.add(hy2);
      }
      // 检查到是shadowsocks类型的节点
    } else if (["ss", "shadowsocks"].includes(proxyType)) {
      let ss = parse_shadowsocks(outbounds[i]);
      if (ss) {
        uniqueSet.add(ss);
      }
      // 检查到是vless类型的节点
    } else if (proxyType === "vless") {
      let vless = parse_vless(outbounds[i]);
      if (vless) {
        uniqueSet.add(vless);
      }
      // 检查到是vmess类型的节点
    } else if (proxyType === "vmess") {
      let vmess = parse_vmess(outbounds[i]);
      if (vmess) {
        uniqueSet.add(vmess)
      }
      // 检查到是trojan类型的节点
    } else if (proxyType === "trojan") {
      let trojan = parse_trojan(outbounds[i]);
      if (trojan) {
        uniqueSet.add(trojan);
      }
      // 检查到是tuic类型的节点
    } else if (proxyType === "tuic") {
      let tuic = parse_tuic(outbounds[i]);
      if (tuic) {
        uniqueSet.add(tuic);
      }
    }
  }
  // 转换为数组
  const uniqueArray = Array.from(uniqueSet);

  // return btoa(uniqueArray.join('\n'));
  return Base64.encode(uniqueArray.join('\n'));
}


async function fetchData(url) {
  try {
    const result = await axios({
      url,
      headers: {
        "User-Agent": "ClashX Pro/1.72.0.4 (com.west2online.ClashXPro; build:1.72.0.4; macOS 12.0.1) Alamofire/5.4.4",
      },
      timeout: 30 * 1000
    });
    // console.log(result.headers['subscription-userinfo'] || '没有');
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





async function updateProxyNames(proxies) {
  // 遍历每个代理对象
  for (let i = 0; i < proxies.length; i++) {
    const proxy = proxies[i]; // 获取当前代理对象
    const server = proxy.server; // 获取代理的服务器地址

    try {
      // 获取国家代码和相关信息
      // const { ip, country_code, name_emoji } = await getCountryCode(server);

      // 根据代理数量动态生成名称
      if (proxies.length >= 999) {
        proxy.name = `${server}-${i.toString().padStart(4, '0')}`;
      } else if (proxies.length <= 999 && proxies.length > 99) {
        proxy.name = `${server}-${i.toString().padStart(3, '0')}`;
      } else if (proxies.length <= 99) {
        proxy.name = `${server}-${i.toString().padStart(2, '0')}`;
      }
    } catch (error) {
      // 捕获并记录错误
      console.error(`Error processing proxy with server ${server}:`, error);
    }
  }

  // 返回更新后的代理数组
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

  console.log(`Fetching subscribe url: ${url}`);


  // 1、http get
  let urlRes = await fetchData(url);
  let urlResData = urlRes.data;
  // let USER_INFO = 'upload=0; download=0; total=2748779069440'
  let USER_INFO = 'upload=0; download=0; total=10737418240000000; expire=2546249531';

  if (urlRes.headers['subscription-userinfo']) {
    USER_INFO = urlRes.headers['subscription-userinfo'];
  }

  if (!urlResData) {
    res.status(400).send(`Fetching subscribe url failed`);
    return
  }

  let proxiesArr = []


  // 从proxieos和provider中提取代理
  // 2、proxies
  console.log(`Extract: proxies`);
  try {
    let proxies = [];
    let yaml_parse = YAML.parse(urlResData);

    if (yaml_parse['proxies']) {
      proxies = YAML.parse(urlResData)['proxies'];

    } else {
      if (isV2rayLink(urlResData)) {
        proxies =  ConvertsV2Ray(urlResData);
      } else {
        console.log('The proxies key does not exist or the value is not an array');
      }
    }

    // console.log(proxies)
    if (proxies && Array.isArray(proxies)) {
      proxiesArr.push(...proxies)
    }

  } catch (error) {
    console.log(`YAML.parse(urlResData) 失败`)
    if (isV2rayLink(urlResData)) {
      console.log(`urlResData: ${urlResData}`)
      let proxies = ConvertsV2Ray(urlResData);
      console.log(`proxies: ${JSON.stringify(proxies)}`)
      if (proxies && Array.isArray(proxies)) {
        proxiesArr.push(...proxies)
      }
    } else {
      console.log('Failed to obtain proxies');
    }
  }

  // 3、proxy-providers
  console.log(`Extract: proxy-providers`);
  try {
    let providers = YAML.parse(urlResData)['proxy-providers'];
    let fetchPromises = [];

    for (const val in providers) {
      let url = String(providers[val]['url']);
      console.log(`Fetching providers url: ${url}`);
      fetchPromises.push(fetchData(url).data.then(data => {
        // console.log(`${val}开始请求：${url}`)
        if (data) {
          // console.log(`${val}请求结束：${url}`)
          try {
            let proxies = YAML.parse(data)['proxies'];
            if (proxies && Array.isArray(proxies)) {
              return proxies;
            } else {
              if (isV2rayLink(data)) {
                return ConvertsV2Ray(data);
              } else {
                console.log('The proxies in proxy-providers key does not exist or the value is not an array');
                return [];
              }
            }
          } catch (error) {
            console.log(`proverdes url yaml parse 失败`)
            if (isV2rayLink(data)) {
              return ConvertsV2Ray(data)
            } else {
              return [];
            }
          }
        } else {
          return [];
        }
      }));
    }

    // 并行处理所有的 fetch 请求
    let results = await Promise.all(fetchPromises);

    // 将所有结果合并到 proxiesArr 中
    results.forEach(proxies => {
      proxiesArr.push(...proxies);
    });

  } catch (error) {
    console.log('Failed to obtain proxy-providers');
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

  // 节点cipher有效性筛选
  proxiesArr = proxiesArr.filter(item => {
    if (item.type === 'ss' || item === 'ssr') {
      return ssCipher.includes(item.cipher);
    }
    if (item.type === 'vmess') {
      return vmessCiper.includes(item.cipher);
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

  // proxies 重命名
  // proxiesArr = await updateProxyNames(proxiesArr)

  // 使用反转义函数
  // proxiesArr = proxiesArr.map(proxy => ({
  //   ...proxy, // 保留其他属性
  //   name: unescapeString(proxy.name) // 反转义 name 字段
  // }));



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
    res.setHeader('subscription-userinfo', USER_INFO)
    res.status(200).send(proxies.join("\n"));
  } else if (target === "sub") {
    const response = proxiesToSub(proxiesArr);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('subscription-userinfo', USER_INFO)
    res.status(200).send(response);
  } else {
    let response = YAML.stringify({ proxies: proxiesArr });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('subscription-userinfo', USER_INFO)
    res.status(200).send(response);
  }
};
