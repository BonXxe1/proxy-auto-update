import requests
import time
import re
import json
from collections import defaultdict
import random
import ipaddress

# 指定国家
countries = ['US', 'JP', 'KR', 'SG', 'TW', 'HK']

# 多源配置（仅IPv6）
sources = [
    {'name': 'proxifly_socks5_ipv6', 'url': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt', 'format': 'ip_port_country', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'vakhov_socks5_ipv6', 'url': 'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/main/proxies/socks5.txt', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'TheSpeedX_socks5_ipv6', 'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'jetkai_socks5_ipv6', 'url': 'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'gfpcom_socks5_ipv6', 'url': 'https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/proxies/socks5.txt', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'proxyscrape_socks5_ipv6', 'base_url': 'https://api.proxyscrape.com/v2/?request=get&protocol=socks5&timeout=10000&anonymity=elite', 'format': 'ip_port', 'type': 'api', 'protocol': 'socks5'},
    {'name': 'pubproxy_socks5_ipv6', 'base_url': 'http://pubproxy.com/api/proxy?limit=10&type=socks5', 'format': 'json_ip_port_country', 'type': 'api', 'protocol': 'socks5'},
    {'name': 'proxylister_socks5_ipv6', 'base_url': 'https://proxylister.com/api/proxies?protocol=socks5&anonymity=elite&limit=10', 'format': 'json_ip_port', 'type': 'api', 'protocol': 'socks5'},
    {'name': 'getproxylist_socks5_ipv6', 'base_url': 'https://api.getproxylist.com/proxy?protocol[]=socks5&country[]=US&anonLevel[]=1&limit=10', 'format': 'json_ip_port', 'type': 'api', 'protocol': 'socks5'},
    {'name': 'free-proxy-list.net_socks5_ipv6', 'url': 'https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
    {'name': 'ditatompel_ipv6', 'url': 'https://www.ditatompel.com/proxy/asn/31200', 'format': 'ip_port', 'type': 'txt', 'protocol': 'http'},
    {'name': 'proxydb_socks5_ipv6', 'base_url': 'http://proxydb.net/?protocol=socks5&anonlvl=Elite', 'format': 'ip_port', 'type': 'txt', 'protocol': 'socks5'},
]

def is_ipv6(ip):
    """验证IPv6地址"""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def fetch_from_source(source, country=None):
    """从单个源拉取IPv6代理"""
    proxies = []
    try:
        if source['type'] == 'txt':
            resp = requests.get(source['url'], timeout=15)
            if resp.status_code == 200:
                lines = resp.text.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if ':' in line:
                        if source['format'] == 'ip_port_country' and '#' in line:
                            parts = line.split('#')
                            if len(parts) == 2:
                                ip_port = parts[0].strip()
                                ip = ip_port.split(':')[0]
                                if is_ipv6(ip):
                                    country_code = parts[1].strip()
                                    if country_code in countries:
                                        proxies.append(f"{ip_port}#{country_code}#{source['protocol']}")
                        elif source['format'] == 'ip_port':
                            ip_port = line.strip()
                            ip = ip_port.split(':')[0]
                            if is_ipv6(ip):
                                proxies.append(f"{ip_port}#{country or 'US'}#{source['protocol']}")
                print(f"从 {source['name']} 拉取 {len(proxies)} 个IPv6代理")
            else:
                print(f"{source['name']} 返回状态码: {resp.status_code}")
        elif source['type'] == 'api':
            url = source['base_url'] + (f"&country={country}" if country else "")
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                if 'json' in source['format']:
                    data = resp.json()
                    for item in data.get('data', data.get('proxies', [])):
                        ip = item.get('ip', item.get('ipPort', '')).split(':')[0]
                        port = item.get('port', '')
                        ip_port = item.get('ipPort', f"{ip}:{port}")
                        country_code = item.get('country', 'US')
                        if is_ipv6(ip) and country_code in countries:
                            proxies.append(f"{ip_port}#{country_code}#{source['protocol']}")
                else:
                    lines = resp.text.strip().split('\n')
                    for line in lines:
                        ip_port = line.strip()
                        ip = ip_port.split(':')[0]
                        if is_ipv6(ip):
                            proxies.append(f"{ip_port}#{country or 'US'}#{source['protocol']}")
                print(f"从 {source['name']} 拉取 {len(proxies)} 个IPv6代理")
            else:
                print(f"{source['name']} 返回状态码: {resp.status_code}")
    except Exception as e:
        print(f"{source['name']} 拉取失败: {e}")
    return proxies

def test_proxy(proxy_str):
    """测试IPv6连通性（支持SOCKS5）"""
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
        print(f"测试 {proxy_str} 错误: {str(e)[:50]}...")
        return False, delay

# 主流程
print("开始多源IPv6代理拉取与测试 (2025-11-13)...")
all_proxies = []
for country in countries:
    for source in sources:
        new_proxies = fetch_from_source(source, country)
        all_proxies.extend(new_proxies[:5])  # 每源/国家限5个

# 去重 + 随机
unique_proxies = list(dict.fromkeys(all_proxies))[:50]
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
    else:
        f.write("无成功IPv6代理（可能源不可用或测试全失败）\n")
        print("警告: 无成功代理，写入空提示")

print(f"\n成功IPv6代理: {len(success_proxies)} | 已写入 proxies_success.txt")
print("国家统计:", dict(stats))
