const Base64 = require("js-base64");
const url = require("url");
const YAML = require("yaml");
const vtool = require('./v.js');
const CryptoJS = require('crypto-js');

function isV2rayLink(inputString) {

    if (!inputString) {
        return false;
    }
    if (isBase64(inputString)) {
        return true;
    }

    // 将输入字符串按行分割
    const lines = inputString.split('\n');

    // 遍历每一行
    for (const line of lines) {
        const trimmedLine = line.trim();

        // 忽略空行和注释行
        if (trimmedLine === '' || trimmedLine.startsWith('#')) {
            continue; // 跳过空行和注释行
        }

        console.log('非注释行: ', line);
        if (!line.includes('://')) {
            return false; // 如果不包含则返回 false
        }
        // console.log('包含://行');
        // // 如果该行不是以#开头
        // if (!line.trim().startsWith('#')) {
        //     // 检查该行是否包含 ://
        //     console.log('非注释行: ', line);
        //     if (!line.includes('://')) {
        //         console.log('不含://行');
        //         return false; // 如果不包含则返回 false
        //     }
        //     console.log('包含://行');
        // }
    }

    return true; // 所有符合条件的行都包含 ://，返回 true
}

function isBase64(str) {
    if (!str) {
        return false;
    }

    try {
        CryptoJS.enc.Utf8.stringify(CryptoJS.enc.Base64.parse(str));
        return true;
    }catch (e) {
        return false;
    }
}

function urlEncodedCheck(str) {
    try {
        const decoded = decodeURIComponent(str);
        if (decoded !== str) {
            return decoded;
        }
        return str;
    } catch (e) {
        return str;
    }
}

// Converts V2Ray subscribe proxies data to mihomo proxies config
function ConvertsV2Ray(buf) {
    let data;
    if (isBase64(buf)) {
        data = Base64.decode(buf);
    } else {
        data = buf
    }

    const arr = data.split("\n"); // Split data by newline
    const proxies = []; // Initialize proxies array
    const names = {}; // Initialize names map

    arr.forEach(line => {
        line = line.trimEnd(" \r"); // Trim trailing spaces and carriage returns
        if (line === "") return; // Skip empty lines

        const [scheme, body] = line.split("://"); // Split line by "://"
        if (!body) return; // Skip lines without a body

        const lowerCaseScheme = scheme.toLowerCase(); // Convert scheme to lowercase
        switch (lowerCaseScheme) {
            case "hysteria": {
                const urlHysteria = new url.URL(line);
                const query = new URLSearchParams(urlHysteria.search);
                // const name = uniqueName(names, urlHysteria.hash.slice(1)); // 去掉 '#' 符号
                const name = uniqueName(names, urlEncodedCheck(urlHysteria.hash.slice(1))); // 去掉 '#' 符号
                let hysteria = {};

                hysteria['name'] = name;
                hysteria['type'] = scheme;
                hysteria['server'] = urlHysteria.hostname;
                hysteria['port'] = urlHysteria.port;
                hysteria['sni'] = query.get('peer');
                hysteria['obfs'] = query.get('obfs');

                if (query.get('alpn')) {
                    hysteria['alpn'] = query.get('alpn')?.split(',');
                }
                hysteria['auth_str'] = query.get('auth');
                hysteria['protocol'] = query.get('protocol');
                let up = query.get('up');
                let down = query.get('down');
                if (!up) {
                    up = query.get('upmbps');
                }
                if (!down) {
                    down = query.get('downmbps');
                }
                hysteria['down'] = down;
                hysteria['up'] = up;
                hysteria['skip-cert-verify'] = query.get('insecure') === 'true';

                proxies.push(hysteria);
                break;

            }
            case "hysteria2":
            case "hy2": {
                try {
                    const urlHysteria2 = new url.URL(line);
                    const query = new URLSearchParams(urlHysteria2.searchParams);
                    // const name = uniqueName(names, urlHysteria2.hash.slice(1));
                    const name = uniqueName(names, urlEncodedCheck(urlHysteria2.hash.slice(1)));
                    let hysteria2 = {};

                    hysteria2["name"] = name;
                    hysteria2["type"] = "hysteria2";
                    hysteria2["server"] = urlHysteria2.hostname;
                    if (urlHysteria2.port) {
                        hysteria2["port"] = urlHysteria2.port;
                    } else {
                        hysteria2["port"] = "443";
                    }
                    hysteria2["obfs"] = query.get("obfs");
                    hysteria2["obfs-password"] = query.get("obfs-password");
                    hysteria2["sni"] = query.get("sni");
                    hysteria2["skip-cert-verify"] = query.get("insecure") === 'true';

                    if (query.get("alpn")) {
                        hysteria2["alpn"] = query.get("alpn")?.split(',');
                    }
                    if (urlHysteria2.username) {
                        hysteria2["password"] = urlHysteria2.username;
                    }
                    hysteria2["fingerprint"] = query.get("pinSHA256");
                    hysteria2["down"] = query.get("down");
                    hysteria2["up"] = query.get("up");

                    proxies.push(hysteria2);
                } catch (err) {
                    // 如果解析 URL 失败，则继续下一个循环
                    return;
                }
                break;

            }
            case "vless": {
                try {
                    const urlVLess = new url.URL(line);
                    const query = new URLSearchParams(urlVLess.search);
                    let vless = {};
                    const err = vtool.handleVShareLink(names, urlVLess, scheme, vless);
                    if (err) {
                        // log.warn(`error:${err.message} line:${line}`);
                        return;
                    }

                    if (query.get('flow')) {
                        vless['flow'] = query.get('flow').toLowerCase();
                    }
                    proxies.push(vless);
                } catch (err) {
                    // 如果解析 URL 失败，则继续下一个循环
                    return;
                }
                break;
            }

            case "vmess": {
                let dcBuf;
                if (isBase64(body)) {
                    dcBuf = Base64.decode(body);
                } else {
                    const urlVMess = new url.URL(line);
                    const query = new URLSearchParams(urlVMess.search);
                    let vmess = {};
                    const err = vtool.handleVShareLink(names, urlVMess, scheme, vmess);
                    if (err) {
                        // log.warn(`error:${err.message} line:${line}`);
                        return;
                    }
                    vmess['alterId'] = 0;
                    vmess['cipher'] = 'auto';

                    if (query.get('encryption')) {
                        vmess['cipher'] = encryption;
                    }

                    proxies.push(vmess);
                    return;
                }

                let values;
                try {
                    values = JSON.parse(dcBuf);
                } catch (e) {
                    return;
                }
                if (!values.ps || typeof values.ps !== 'string') {
                    return;
                }
                const name = uniqueName(names, urlEncodedCheck(values.ps));

                let vmess = {
                    name: name,
                    type: lowerCaseScheme,
                    server: values.add,
                    port: values.port,
                    uuid: values.id,
                    alterId: values.aid || 0,
                    udp: true,
                    xudp: true,
                    tls: false,
                    "skip-cert-verify": false,
                    cipher: values.scy || "auto"
                };
                if (values["sni"]) {
                    vmess["servername"] = values["sni"];
                }

                let network;
                if (values["net"]) {
                    network = values["net"].toLowerCase()
                }

                if (values["type"] === 'http') {
                    network = "http"
                } else if (network === "http") {
                    network = "h2"
                }
                vmess["network"] = network

                if (values.tls && values.tls.toLowerCase().endsWith("tls")) {
                    vmess["tls"] = true;
                    if (values.alpn) {
                        vmess["alpn"] = values.alpn.split(",");
                    }
                }

                switch (vmess["network"]) {
                    case "http": {
                        vmess["http-opts"] = {
                            path: values["path"] ? values["path"] : "/",
                            headers: {
                                Host: values["host"] ? values["host"] : undefined
                            }
                        };
                        break;
                    }

                    case "h2": {
                        vmess["h2-opts"] = {
                            path: values["path"] ? values["path"] : undefined,
                            headers: values["host"] ? values["host"] : undefined
                        };
                        break;
                    }

                    case "ws":
                    case "httpupgrade": {
                        let headers = {}
                        let wsOpts = {}
                        wsOpts["path"] = "/";
                        if (values["host"]) {
                            headers["Host"] = values["host"]
                        }
                        if (values["path"]) {
                            let path = values["path"]
                            let pathURL;
                            try {
                                pathURL = new URL(path);
                                let query = pathURL.searchParams;
                                let earlyData = query.get("ed");

                                if (earlyData && earlyData !== "") {
                                    const med = parseInt(earlyData, 10);
                                    if (!isNaN(med)) {
                                        switch (values.network) {
                                            case "ws":
                                                wsOpts["max-early-data"] = med;
                                                wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol";
                                                break;
                                            case "httpupgrade":
                                                wsOpts["v2ray-http-upgrade-fast-open"] = true;
                                                break;
                                        }
                                        query.delete("ed");
                                        pathURL.search = query.toString();
                                        path = pathURL.toString();
                                    }
                                }

                                let earlyDataHeader = query.get("eh");
                                if (earlyDataHeader && earlyDataHeader !== "") {
                                    wsOpts["early-data-header-name"] = earlyDataHeader;
                                }
                                wsOpts["path"] = path;
                            } catch (e) {
                            }
                        }

                        wsOpts["headers"] = headers
                        vmess["ws-opts"] = wsOpts
                        break;
                    }
                    case "grpc": {
                        vmess["grpc-opts"] = {
                            "grpc-service-name": values.path ? values.path : undefined
                        };
                        break;
                    }
                }

                proxies.push(vmess); // Add to proxies array
                break;
            }
            case "tuic": {
                try {
                    const urlTUIC = new url.URL(line);
                    const query = new URLSearchParams(urlTUIC.searchParams);
                    let tuic = {};

                    tuic["name"] = uniqueName(names, urlEncodedCheck(urlTUIC.hash.slice(1)));
                    tuic["type"] = "tuic"; // 假设 scheme 是 "tuic"
                    tuic["server"] = urlTUIC.hostname;
                    tuic["port"] = urlTUIC.port;
                    tuic["udp"] = true;

                    if (urlTUIC.password) {
                        tuic["uuid"] = urlTUIC.username;
                        tuic["password"] = urlTUIC.password;
                    } else {
                        tuic["token"] = urlTUIC.username;
                    }

                    if (query.get("congestion_control")) {
                        tuic["congestion-controller"] = query.get("congestion_control");
                    }
                    if (query.get("alpn")) {
                        tuic["alpn"] = query.get("alpn")?.split(",");
                    }
                    if (query.get("sni")) {
                        tuic["sni"] = query.get("sni");
                    }
                    if (query.get("disable_sni") === "1") {
                        tuic["disable-sni"] = true;
                    }
                    if (query.get("udp_relay_mode")) {
                        tuic["udp-relay-mode"] = query.get("udp_relay_mode");
                    }
                    proxies.push(tuic);
                } catch (err) {
                    // 如果解析 URL 失败，则继续下一个循环
                    return;
                }
                break;

            }
            case "trojan": {
                try {
                    const urlTrojan = new url.URL(line);
                    const query = new URLSearchParams(urlTrojan.searchParams);
                    const name = uniqueName(names, urlEncodedCheck(urlTrojan.hash.slice(1)));
                    let trojan = {};

                    trojan["name"] = name;
                    trojan["type"] = "trojan"; // 假设 scheme 是 "trojan"
                    trojan["server"] = urlTrojan.hostname;
                    trojan["port"] = urlTrojan.port
                    trojan["password"] = urlTrojan.username;
                    trojan["udp"] = true;
                    trojan["skip-cert-verify"] = query.get("allowInsecure") === "true";

                    if (query.get("sni")) {
                        trojan["sni"] = query.get("sni");
                    }
                    if (query.get("alpn")) {
                        trojan["alpn"] = query.get("alpn").split(",");
                    }

                    const network = query.get("type")?.toLowerCase();
                    if (network) {
                        trojan["network"] = network;
                    }

                    switch (network) {
                        case "ws": {
                            let headers = {};
                            let wsOpts = {};

                            headers["User-Agent"] = vtool.RandUserAgent();

                            wsOpts["path"] = query.get("path");
                            wsOpts["headers"] = headers;

                            trojan["ws-opts"] = wsOpts;
                            break;
                        }

                        case "grpc": {
                            const grpcOpts = {};
                            grpcOpts["grpc-service-name"] = query.get("serviceName");
                            trojan["grpc-opts"] = grpcOpts;
                            break;
                        }
                    }

                    if (query.get("fp")) {
                        trojan["client-fingerprint"] = query.get("fp");
                    } else {
                        trojan["client-fingerprint"] = "chrome";
                    }

                    proxies.push(trojan);
                } catch (err) {
                    // 如果解析 URL 失败，则继续下一个循环
                    return;
                }
                break;
            }
            case "ss": {
                try {
                    const urlSS = new url.URL(line);
                    let name = uniqueName(names, urlEncodedCheck(urlSS.hash.slice(1)));
                    let port = urlSS.port;

                    if (!port) {
                        const dcBuf = base64.decode(urlSS.host); // 假设 encRaw.DecodeString 是 base64 解码
                        const newUrl = "ss://" + dcBuf;
                        const newUrlSS = new url.URL(newUrl);
                        if (!newUrlSS.port) {
                            return;
                        }
                        urlSS.host = newUrlSS.host;
                        urlSS.port = newUrlSS.port;
                    }

                    let cipherRaw = urlSS.username;
                    let cipher = cipherRaw;
                    let password = urlSS.password;
                    let found = password !== undefined;

                    if (!found) {
                        let dcBuf = base64.decode(cipherRaw); // 假设 base64.RawURLEncoding.DecodeString 是 base64 解码
                        if (!dcBuf) {
                            dcBuf = base64.decode(cipherRaw); // 假设 enc.DecodeString 是 base64 解码
                        }
                        [cipher, password] = dcBuf.split(':');
                        found = password !== undefined;
                        if (!found) {
                            return;
                        }
                        const err = VerifyMethod(cipher, password);
                        if (err) {
                            dcBuf = base64.decode(cipherRaw); // 假设 encRaw.DecodeString 是 base64 解码
                            [cipher, password] = dcBuf.split(':');
                        }
                    }

                    const ss = {};

                    ss["name"] = name;
                    ss["type"] = "ss"; // 假设 scheme 是 "ss"
                    ss["server"] = urlSS.hostname;
                    ss["port"] = urlSS.port;
                    ss["cipher"] = cipher;
                    ss["password"] = password;
                    const query = new URLSearchParams(urlSS.searchParams);
                    ss["udp"] = true;
                    if (query.get("udp-over-tcp") === "true" || query.get("uot") === "1") {
                        ss["udp-over-tcp"] = true;
                    }
                    const plugin = query.get("plugin");
                    if (plugin && plugin.includes(";")) {
                        const pluginInfo = new URLSearchParams("pluginName=" + plugin.replaceAll(";", "&"));
                        const pluginName = pluginInfo.get("pluginName");
                        if (pluginName.includes("obfs")) {
                            ss["plugin"] = "obfs";
                            ss["plugin-opts"] = {
                                "mode": pluginInfo.get("obfs"),
                                "host": pluginInfo.get("obfs-host"),
                            };
                        } else if (pluginName.includes("v2ray-plugin")) {
                            ss["plugin"] = "v2ray-plugin";
                            ss["plugin-opts"] = {
                                "mode": pluginInfo.get("mode"),
                                "host": pluginInfo.get("host"),
                                "path": pluginInfo.get("path"),
                                "tls": plugin.includes("tls"),
                            };
                        }
                    }

                    proxies.push(ss);
                } catch (err) {
                    // 如果解析 URL 失败，则继续下一个循环
                    return;
                }
                break;
            }
            case "ssr": {
                function decodeUrlSafe(encoded) {
                    return Base64.decode(encoded?.replace(/-/g, '+').replace(/_/g, '/'));
                }

                function urlSafe(str) {
                    return str?.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                }

                try {
                    const dcBuf = Base64.decode(body); // 假设 encRaw.DecodeString 是 Base64 解码
                    const [before, after] = dcBuf.split('/?');
                    if (!after) {
                        return;
                    }

                    const beforeArr = before.split(':');
                    if (beforeArr.length !== 6) {
                        return;
                    }

                    const host = beforeArr[0];
                    const port = beforeArr[1];
                    const protocol = beforeArr[2];
                    const method = beforeArr[3];
                    const obfs = beforeArr[4];
                    const password = decodeUrlSafe(beforeArr[5]);

                    const query = new URLSearchParams(urlSafe(after));

                    const remarks = decodeUrlSafe(query.get("remarks"));
                    const name = uniqueName(names, urlEncodedCheck(remarks));

                    const obfsParam = decodeUrlSafe(query.get("obfsparam"));
                    const protocolParam = query.get("protoparam");

                    const ssr = {};

                    ssr["name"] = name;
                    ssr["type"] = "ssr"; // 假设 scheme 是 "ssr"
                    ssr["server"] = host;
                    ssr["port"] = port;
                    ssr["cipher"] = method;
                    ssr["password"] = password;
                    ssr["obfs"] = obfs;
                    ssr["protocol"] = protocol;
                    ssr["udp"] = true;

                    if (obfsParam) {
                        ssr["obfs-param"] = obfsParam;
                    }

                    if (protocolParam) {
                        ssr["protocol-param"] = protocolParam;
                    }

                    proxies.push(ssr);
                } catch (err) {
                    // 如果解析失败，则继续下一个循环
                    return;
                }
                break;
            }

        }
    });

    /*if (proxies.length === 0) {
        throw new Error("convert v2ray subscribe error: format invalid");
    }*/

    cleanObject(proxies);
    return proxies;
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

function cleanObject(obj) {
    if (!obj || typeof obj !== 'object') return obj;

    Object.keys(obj).forEach(key => {
        if (obj[key] === undefined || obj[key] === null || obj[key] === '') {
            delete obj[key];
        } else if (typeof obj[key] === 'object') {
            cleanObject(obj[key]);
            if (Array.isArray(obj[key]) && obj[key].length === 0) {
                delete obj[key];
            } else if (!Array.isArray(obj[key]) && Object.keys(obj[key]).length === 0) {
                delete obj[key];
            }
        }
    });

    return obj;
}


module.exports = { ConvertsV2Ray, isBase64, isV2rayLink, urlEncodedCheck };
