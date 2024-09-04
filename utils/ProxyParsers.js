import { parseServerInfo, parseUrlParams, createTlsConfig, createTransportConfig, decodeBase64 } from './utils.js';


export class ProxyParser {

    static parse(url) {
        const type = url.split('://')[0];
        switch (type) {
            case 'ss':
                return new ShadowsocksParser().parse(url);
            case 'vmess':
                return new VmessParser().parse(url);
            case 'vless':
                return new VlessParser().parse(url);
            case 'hysteria2':
                return new Hysteria2Parser().parse(url);
            case 'http':
            case 'https':
                return HttpParser.parse(url);
            case 'trojan':
                return new TrojanParser().parse(url);
            case 'tuic':
                return new TuicParser().parse(url);
        }
    }

    static coverToClashProxies(url) {
        return new CoverToClash().cover(this.parse(url));
    }
}
    class CoverToClash {
        cover(proxy) {
            switch(proxy.type) {
                case 'shadowsocks':
                    return {
                        name: proxy.tag,
                        type: 'ss',
                        server: proxy.server,
                        port: proxy.server_port,
                        cipher: proxy.method,
                        password: proxy.password
                    };
                case 'vmess':
                    return {
                        name: proxy.tag,
                        type: proxy.type,
                        server: proxy.server,
                        port: proxy.server_port,
                        uuid: proxy.uuid,
                        alterId: proxy.alter_id,
                        cipher: proxy.security,
                        tls: proxy.tls?.enabled || false,
                        servername: proxy.tls?.server_name || '',
                        network: proxy.transport?.type || 'tcp',
                        'ws-opts': proxy.transport?.type === 'ws' ? {
                            path: proxy.transport.path,
                            headers: proxy.transport.headers
                        } : undefined
                    };
                case 'vless':
                    return {
                        name: proxy.tag,
                        type: proxy.type,
                        server: proxy.server,
                        port: proxy.server_port,
                        uuid: proxy.uuid,
                        cipher: proxy.security,
                        tls: proxy.tls?.enabled || false,
                        'client-fingerprint': proxy.tls.utls?.fingerprint,
                        servername: proxy.tls?.server_name || '',
                        network: proxy.transport?.type || 'tcp',
                        'ws-opts': proxy.transport?.type === 'ws' ? {
                            path: proxy.transport.path,
                            headers: proxy.transport.headers
                        }: undefined,
                        'reality-opts': proxy.tls.reality?.enabled ? {
                            'public-key': proxy.tls.reality.public_key,
                            'short-id': proxy.tls.reality.short_id,
                        } : undefined,
                        'grpc-opts': proxy.transport?.type === 'grpc' ? {
                            'grpc-mode': 'gun',
                            'grpc-service-name': proxy.transport.service_name,
                        } : undefined,
                        tfo : proxy.tcp_fast_open,
                        'skip-cert-verify': proxy.tls.insecure,
                        'flow': proxy.flow ?? undefined,
                    };
                case 'hysteria2':
                    return {
                        name: proxy.tag,
                        type: proxy.type,
                        server: proxy.server,
                        port: proxy.server_port,
                        obfs: proxy.obfs.type,
                        'obfs-password': proxy.obfs.password,
                        password: proxy.password,
                        auth: proxy.password,
                        'skip-cert-verify': proxy.tls.insecure,
                    };
                case 'trojan':
                    return {
                        name: proxy.tag,
                        type: proxy.type,
                        server: proxy.server,
                        port: proxy.server_port,
                        password: proxy.password,
                        cipher: proxy.security,
                        tls: proxy.tls?.enabled || false,
                        'client-fingerprint': proxy.tls.utls?.fingerprint,
                        servername: proxy.tls?.server_name || '',
                        network: proxy.transport?.type || 'tcp',
                        'ws-opts': proxy.transport?.type === 'ws' ? {
                            path: proxy.transport.path,
                            headers: proxy.transport.headers
                        }: undefined,
                        'reality-opts': proxy.tls.reality?.enabled ? {
                            'public-key': proxy.tls.reality.public_key,
                            'short-id': proxy.tls.reality.short_id,
                        } : undefined,
                        'grpc-opts': proxy.transport?.type === 'grpc' ? {
                            'grpc-mode': 'gun',
                            'grpc-service-name': proxy.transport.service_name,
                        } : undefined,
                        tfo : proxy.tcp_fast_open,
                        'skip-cert-verify': proxy.tls.insecure,
                        'flow': proxy.flow ?? undefined,
                    }
                case 'tuic':
                    return {
                        name: proxy.tag,
                        type: proxy.type,
                        server: proxy.server,
                        port: proxy.server_port,
                        uuid: proxy.uuid,
                        password: proxy.password,
                        'congestion-controller': proxy.congestion,
                        'skip-cert-verify': proxy.tls.insecure,
                    };
                default:
                    return null; // Return as-is if no specific conversion is defined
            }
        }
    }

	class ShadowsocksParser {
		parse(url) {
            let parts = url.replace('ss://', '').split('#');
            let mainPart = parts[0];
            let tag = parts[1];
        
            let [base64, serverPart] = mainPart.split('@');
            let [method, password] = atob(base64).split(':');
        
            // 匹配 IPv6 地址
            let match = serverPart.match(/\[([^\]]+)\]:(\d+)/);
            let server, server_port;
        
            if (match) {
                server = match[1];
                server_port = match[2];
            } else {
                [server, server_port] = serverPart.split(':');
            }
        
            return {
                "tag": tag,
                "type": 'shadowsocks',
                "server": server,
                "server_port": parseInt(server_port),
                "method": method,
                "password": password,
                "network": 'tcp',
                "tcp_fast_open": false
            }
		}
	}

	class VmessParser {
		parse(url) {
            let base64 = url.replace('vmess://', '')
            let vmessConfig = JSON.parse(atob(base64))
            let tls = { "enabled": false }
            let transport = {}
            if (vmessConfig.net === 'ws') {
                transport = {
                    "type": "ws",
                    "path": vmessConfig.path,
                    "headers": { 'Host': vmessConfig.host? vmessConfig.host : vmessConfig.sni  }
                }
                if (vmessConfig.tls !== '') {
                    tls = {
                        "enabled": true,
                        "server_name": vmessConfig.sni,
                        "insecure": false
                    }
                }
            }
            return {
                "tag": vmessConfig.ps,
                "type": "vmess",
                "server": vmessConfig.add,
                "server_port": parseInt(vmessConfig.port),
                "uuid": vmessConfig.id,
                "alter_id": parseInt(vmessConfig.aid),
                "security": vmessConfig.scy,
                "network": "tcp",
                "tcp_fast_open": false,
                "transport": transport,
                "tls": tls.enabled ? tls : undefined
            }

		}
	}

    class VlessParser {
        parse(url) {
          const { addressPart, params, name } = parseUrlParams(url);
          const [uuid, serverInfo] = addressPart.split('@');
          const { host, port } = parseServerInfo(serverInfo);
      
          const tls = createTlsConfig(params);
          const transport = params.type !== 'tcp' ? createTransportConfig(params) : undefined;
      
          return {
            type: "vless",
            tag: name,
            server: host,
            server_port: port,
            uuid: uuid,
            tcp_fast_open: false,
            tls: tls,
            transport: transport,
            network: "tcp",
            flow: params.flow ?? undefined
          };
        }
      }
      
      class Hysteria2Parser {
        parse(url) {
          const { addressPart, params, name } = parseUrlParams(url);
          const [uuid, serverInfo] = addressPart.split('@');
          const { host, port } = parseServerInfo(serverInfo);
      
          const tls = {
            enabled: true,
            server_name: params.sni,
            insecure: true,
            alpn: ["h3"],
          };

          const obfs = {};
          if (params['obfs-password']) {
            obfs.type = params.obfs;
            obfs.password = params['obfs-password'];
          };
      
          return {
            tag: name,
            type: "hysteria2",
            server: host,
            server_port: port,
            password: uuid,
            tls: tls,
            obfs: obfs,
            up_mbps: 100,
            down_mbps: 100
          };
        }
      }

      class TrojanParser {
        parse(url) {
          const { addressPart, params, name } = parseUrlParams(url);
          const [password, serverInfo] = addressPart.split('@');
          const { host, port } = parseServerInfo(serverInfo);

          const parsedURL = parseServerInfo(addressPart);
          const tls = createTlsConfig(params);
          const transport = params.type !== 'tcp' ? createTransportConfig(params) : undefined;
          return {
            type: 'trojan',
            tag: name,
            server: host,
            server_port: port,
            password: password || parsedURL.username,
            network: "tcp",
            tcp_fast_open: false,
            tls: tls,
            transport: transport,
            flow: params.flow ?? undefined
          };
        }
      }

      class TuicParser {
        parse(url) {
          const { addressPart, params, name } = parseUrlParams(url);
          const [userinfo, serverInfo] = addressPart.split('@');
          const { host, port } = parseServerInfo(serverInfo);
      
          const tls = {
            enabled: true,
            server_name: params.sni,
            alpn: [params.alpn],
          };
      
          return {
            tag: name,
            type: "tuic",
            server: host,
            server_port: port,
            uuid: userinfo.split(':')[0],
            password: userinfo.split(':')[1],
            congestion_control: params.congestion_control,
            tls: tls,
            flow: params.flow ?? undefined
          };
        }
      }
      

      class HttpParser {
        static async parse(url) {
            try {
                const response = await fetch(url);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const text = await response.text();
                let decodedText;
                try {
                    decodedText = decodeBase64(text.trim());
                } catch (e) {
                    decodedText = text;
                }
                return decodedText.split('\n').filter(line => line.trim() !== '');
            } catch (error) {
                console.error('Error fetching or parsing HTTP(S) content:', error);
                return null;
            }
        }
    }
