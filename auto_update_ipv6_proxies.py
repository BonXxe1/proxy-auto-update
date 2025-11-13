import requests
import time
import re
import json
import random
from collections import defaultdict
import ipaddress
import ipaddress.IPv6Network  # 用于CIDR解析

# 指定国家
countries = ['US', 'JP', 'KR', 'SG', 'TW', 'HK']

# 18个源（添加Cloudflare优选IPv6源）
sources = [
    # 原15个源（简略，保持不变）
    {'name': 'prxchk_socks5_ipv6', 'url': 'https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'ShiftyTR_api_ipv6', 'base_url': 'https://www.proxyscan.io/api/proxy?limit=10&uptime=50&ping=100', 'format': 'json_ip_port', 'type': 'api', 'protocol': 'socks5'},
    {'name': 'proxyscan_api_ipv6', 'base_url': 'https://www.proxyscan.io/api/proxy?limit=10&type=socks5', 'format': 'json_ip_port', 'type': 'api', 'protocol': 'socks5'},
    {'name': 'clarketm_raw_ipv6', 'url': 'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'advanced_name_socks5', 'url': 'https://advanced.name/freeproxy?type=socks5', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'spys_one_socks', 'url': 'https://spys.one/en/socks-proxy-list/', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'hide_mn_api', 'base_url': 'https://hide.mn/api/proxies?limit=10&type=socks5', 'format': 'json_ip_port_country', 'type': 'api', 'protocol': 'socks5'},
    {'name': 'oxylabs_free_ipv6', 'url': 'https://oxylabs.io/products/free-proxies/api?protocol=socks5', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'TheSpeedX_socks5_ipv6', 'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'jetkai_socks5_ipv6', 'url': 'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'gfpcom_socks5_ipv6', 'url': 'https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/proxies/socks5.txt', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'proxyscrape_socks5_ipv6', 'base_url': 'https://api.proxyscrape.com/v2/?request=get&protocol=socks5&timeout=10000&anonymity=elite', 'format': 'ip_port', 'type': 'api', 'protocol': 'socks5'},
    {'name': 'pubproxy_socks5_ipv6', 'base_url': 'http://pubproxy.com/api/proxy?limit=10&type=socks5', 'format': 'json_ip_port_country', 'type': 'api', 'protocol': 'socks5'},
    {'name': 'proxylister_socks5_ipv6', 'base_url': 'https://proxylister.com/api/proxies?protocol=socks5&anonymity=elite&limit=10', 'format': 'json_ip_port', 'type': 'api', 'protocol': 'socks5'},
    {'name': 'getproxylist_socks5_ipv6', 'base_url': 'https://api.getproxylist.com/proxy?protocol[]=socks5&country[]=US&anonLevel[]=1&limit=10', 'format': 'json_ip_port', 'type': 'api', 'protocol': 'socks5'},
    # 新添加Cloudflare优选IPv6源
    {'name': 'cloudflare_ips_v6', 'url': 'https://www.cloudflare.com/ips-v6/', 'format': 'cidr_list', 'type': 'txt', 'protocol': 'http'},  # 官方CIDR
    {'name': 'davie3_cf_ipv6', 'url': 'https://raw.githubusercontent.com/Davie3/mikrotik-cloudflare-iplist/main/cloudflare-ips-v6.rsc', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},  # GitHub列表
    {'name': 'ircfspace_cf_ips', 'url': 'https://raw.githubusercontent.com/ircfspace/cf-ip-ranges/main/cloudflare-ipv6.json', 'format': 'json_cidr', 'type': 'json', 'protocol': 'http'},  # JSON范围
]

def is_ipv6(ip):
    """验证IPv6地址"""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def generate_random_ipv6_from_cidr(cidr):
    """从CIDR生成随机IPv6 IP"""
    try:
        network = ipaddress.IPv6Network(cidr, strict=False)
        return str(random.choice(list(network.hosts()))[:19])  # 随机主机IP
    except:
        return None

def fetch_from_source(source, country=None):
    """从单个源拉取IPv6代理（支持Cloudflare CIDR解析）"""
    proxies = []
    try:
        resp = requests.get(source['url'], timeout=15)
        if resp.status_code == 200:
            if source['format'] == 'cidr_list' or source['format'] == 'json_cidr':
                # Cloudflare CIDR解析
                lines = resp.text.strip().split('\n')
                cidrs = []
                if source['format'] == 'json_cidr':
                    data = resp.json()
                    cidrs = data.get('ipv6_cidrs', [])
                else:
                    cidrs = [line.strip() for line in lines if '/' in line]
                count = 0
                for cidr in cidrs:
                    if count < 10:  # 限10个CIDR
                        random_ip = generate_random_ipv6_from_cidr(cidr)
                        if random_ip and is_ipv6(random_ip):
                            port = random.randint(80, 1080)  # 随机端口
                            ip_port = f"[{random_ip}]:{port}"
                            proxies.append(f"{ip_port}#{country or 'US'}#{source['protocol']}")
                            count += 1
                print(f"从 {source['name']} 解析 {len(proxies)} 个Cloudflare IPv6代理")
            else:
                # 原有TXT/JSON逻辑（简略）
                lines = resp.text.strip().split('\n')
                count = 0
                for line in lines:
                    if ':' in line and count < 20:
                        ip_port = line.strip()
                        ip = ip_port.split(':')[0]
                        if is_ipv6(ip):
                            proxies.append(f"{ip_port}#{country or 'US'}#{source['protocol']}")
                            count += 1
                print(f"从 {source['name']} 拉取 {len(proxies)} 个IPv6代理")
        else:
            print(f"{source['name']} 状态码: {resp.status_code}")
    except Exception as e:
        print(f"{source['name']} 失败: {e}")
    return proxies

def test_proxy(proxy_str):
    """测试IPv6连通性"""
    parts = proxy_str.split('#')
    proxy_addr = parts[0]
    protocol = parts[2] if len(parts) > 2 else 'http'
    proxy_dict = {
        'http': f"{protocol}://{proxy_addr}",
        'https': f"{protocol}://{proxy_addr}"
    }
    start_time = time.time()
    try:
        resp = requests.get('https://httpbin.org/ip', proxies=proxy_dict, timeout=15)
        delay = round(time.time() - start_time, 2)
        return resp.status_code == 200 and delay < 10, delay
    except Exception as e:
        delay = round(time.time() - start_time, 2)
        return False, delay

# 主流程
print("开始多源IPv6代理拉取与测试 (2025-11-13，含Cloudflare优选)...")
all_proxies = []
for country in countries:
    for source in sources:
        new_proxies = fetch_from_source(source, country)
        all_proxies.extend(new_proxies[:5])

# 去重 + 随机
unique_proxies = list(dict.fromkeys(all_proxies))[:60]
random.shuffle(unique_proxies)
print(f"总独特IPv6代理: {len(unique_proxies)}")

# 测试连通性
success_proxies = []
stats = defaultdict(int)
for proxy in unique_proxies:
    success, delay = test_proxy(proxy)
    if success:
        success_proxies.append(proxy)
        stats[proxy.split('#')[1]] += 1
    print(f"测试 {proxy} - {'成功' if success else '失败'} (延迟: {delay}s)")
    time.sleep(0.5)

# 强制写入proxies_success.txt
with open('proxies_success.txt', 'w') as f:
    if success_proxies:
        for proxy in success_proxies:
            f.write(proxy + '\n')
        print(f"写入 {len(success_proxies)} 个成功IPv6代理（含Cloudflare）")
    else:
        f.write("无可用IPv6代理 - 尝试付费Cloudflare Workers\n")
        print("警告: 无成功代理，写入空提示")

print(f"\n成功IPv6代理: {len(success_proxies)} | 已写入 proxies_success.txt")
print("国家统计:", dict(stats))
