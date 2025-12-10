#!/usr/bin/env python3
"""
더미 IIS 로그 생성기
- 24개 정찰 도구의 전형적인 행동 패턴 시뮬레이션
- IIS W3C 로그 형식 준수
"""

import random
from datetime import datetime, timedelta

# ============================================================================
# 도구별 시그니처 및 행동 패턴
# ============================================================================

RECON_TOOLS = {
    # Directory Bruteforce (7개)
    'nikto': {
        'user_agent': 'Nikto/2.5.0',
        'patterns': [
            '/admin/', '/backup/', '/test/', '/.git/', '/config/',
            '/phpMyAdmin/', '/wp-admin/', '/.svn/', '/cgi-bin/',
        ],
        'extensions': ['.php', '.asp', '.jsp', '.cgi', '.pl', '.py', '.sh', '.bak', '.old', '.txt', '.sql', '.log'],
        'random_strings': True,  # 무작위 8자 문자열 사용
        'requests_per_second': 50,
        'duration_seconds': 30,
        'status_codes': {'404': 90, '403': 5, '200': 5},
    },
    'gobuster': {
        'user_agent': 'gobuster/3.8',
        'patterns': [
            '/admin', '/api', '/backup', '/config', '/database',
            '/dev', '/test', '/uploads', '/assets', '/static',
        ],
        'extensions': ['.php', '.html', '.txt', '.zip', '.tar', '.gz', '.bak'],
        'random_strings': False,
        'requests_per_second': 200,
        'duration_seconds': 10,
        'status_codes': {'404': 95, '200': 3, '403': 2},
    },
    'dirbuster': {
        'user_agent': 'DirBuster-1.0-RC1',
        'patterns': [
            '/admin/', '/backup/', '/test/', '/dev/', '/old/',
            '/temp/', '/logs/', '/data/', '/files/', '/images/',
        ],
        'extensions': ['.php', '.asp', '.aspx', '.jsp', '.html', '.xml', '.bak'],
        'random_strings': False,
        'requests_per_second': 80,
        'duration_seconds': 20,
        'status_codes': {'404': 92, '200': 5, '403': 3},
    },
    'dirb': {
        'user_agent': 'dirb/2.22',
        'patterns': [
            '/admin', '/backup', '/test', '/tmp', '/config',
            '/db', '/sql', '/php', '/cgi', '/bin',
        ],
        'extensions': ['.php', '.html', '.txt', '.bak'],
        'random_strings': False,
        'requests_per_second': 60,
        'duration_seconds': 15,
        'status_codes': {'404': 88, '200': 8, '403': 4},
    },
    'wfuzz': {
        'user_agent': 'Wfuzz/3.1.0',
        'patterns': [
            '/FUZZ.php', '/admin/FUZZ', '/api/FUZZ', '/FUZZ.html',
        ],
        'extensions': ['.php', '.asp', '.jsp', '.txt'],
        'random_strings': False,
        'requests_per_second': 100,
        'duration_seconds': 12,
        'status_codes': {'404': 85, '200': 10, '500': 5},
    },
    'ffuf': {
        'user_agent': 'ffuf/v2.1.0',
        'patterns': [
            '/admin', '/api', '/backup', '/config', '/dev',
        ],
        'extensions': ['.php', '.html', '.json', '.xml', '.bak'],
        'random_strings': False,
        'requests_per_second': 150,
        'duration_seconds': 8,
        'status_codes': {'404': 93, '200': 5, '403': 2},
    },
    'feroxbuster': {
        'user_agent': 'feroxbuster/2.10.4',
        'patterns': [
            '/admin', '/api', '/backup', '/config', '/data',
        ],
        'extensions': ['.php', '.html', '.txt', '.zip'],
        'random_strings': False,
        'requests_per_second': 120,
        'duration_seconds': 10,
        'status_codes': {'404': 90, '200': 7, '403': 3},
    },
    
    # Web Vulnerability Scanner (6개)
    'arachni': {
        'user_agent': 'Arachni/v2.0',
        'patterns': [
            '/index.php?id=1', '/page.php?id=1', '/view.php?id=1',
            '/search.php?q=test', '/login.php', '/contact.php',
        ],
        'extensions': ['.php', '.asp', '.jsp'],
        'random_strings': False,
        'requests_per_second': 40,
        'duration_seconds': 25,
        'status_codes': {'200': 50, '404': 30, '500': 10, '403': 10},
    },
    'zap': {
        'user_agent': 'Mozilla/5.0 (compatible; OWASP ZAP/2.14.0)',
        'patterns': [
            '/index.php?id=1', '/page.php?id=<script>alert(1)</script>',
            '/search.php?q=\' OR 1=1--', '/login.php', '/admin.php',
        ],
        'extensions': ['.php', '.asp', '.jsp', '.html'],
        'random_strings': False,
        'requests_per_second': 30,
        'duration_seconds': 30,
        'status_codes': {'200': 40, '404': 35, '500': 15, '403': 10},
    },
    'burp': {
        'user_agent': 'Burp Suite Professional/2023.1',
        'patterns': [
            '/api/user', '/api/admin', '/api/config', '/rest/api/user',
        ],
        'extensions': ['.json', '.xml', '.php'],
        'random_strings': False,
        'requests_per_second': 25,
        'duration_seconds': 20,
        'status_codes': {'200': 45, '401': 30, '404': 15, '500': 10},
    },
    'acunetix': {
        'user_agent': 'Acunetix/v24',
        'patterns': [
            '/index.php?id=1', '/page.php?id=1\' OR 1=1--',
            '/search.php', '/login.php', '/admin.php',
        ],
        'extensions': ['.php', '.asp', '.aspx', '.jsp'],
        'random_strings': False,
        'requests_per_second': 35,
        'duration_seconds': 28,
        'status_codes': {'200': 50, '404': 25, '500': 15, '403': 10},
    },
    'nessus': {
        'user_agent': 'Mozilla/5.0 (compatible; Nessus/10.6.0)',
        'patterns': [
            '/', '/index.html', '/robots.txt', '/.git/config', '/admin/',
        ],
        'extensions': ['.html', '.php', '.asp'],
        'random_strings': False,
        'requests_per_second': 20,
        'duration_seconds': 25,
        'status_codes': {'200': 60, '404': 30, '403': 10},
    },
    'openvas': {
        'user_agent': 'OpenVAS/22.4',
        'patterns': [
            '/', '/admin/', '/test/', '/cgi-bin/', '/phpinfo.php',
        ],
        'extensions': ['.php', '.cgi', '.pl'],
        'random_strings': False,
        'requests_per_second': 18,
        'duration_seconds': 22,
        'status_codes': {'200': 55, '404': 35, '403': 10},
    },
    
    # SQL Injection Tool (3개)
    'sqlmap': {
        'user_agent': 'sqlmap/1.8.5',
        'patterns': [
            '/index.php?id=1\' AND 1=1--',
            '/page.php?id=1 UNION SELECT NULL--',
            '/view.php?id=1 AND SLEEP(5)--',
            '/search.php?q=1\' OR \'1\'=\'1',
        ],
        'extensions': ['.php', '.asp', '.jsp'],
        'random_strings': False,
        'requests_per_second': 15,
        'duration_seconds': 35,
        'status_codes': {'200': 40, '500': 30, '404': 20, '403': 10},
    },
    'havij': {
        'user_agent': 'Havij/1.18 Pro',
        'patterns': [
            '/index.php?id=1\' UNION SELECT',
            '/page.php?id=1 AND 1=1',
            '/view.php?id=1\' OR \'1\'=\'1',
        ],
        'extensions': ['.php', '.asp', '.aspx'],
        'random_strings': False,
        'requests_per_second': 12,
        'duration_seconds': 25,
        'status_codes': {'200': 35, '500': 35, '404': 20, '403': 10},
    },
    'pangolin': {
        'user_agent': 'Pangolin/3.2',
        'patterns': [
            '/index.php?id=1 AND 1=1',
            '/page.php?id=1\' UNION ALL SELECT',
            '/view.php?id=1 WAITFOR DELAY',
        ],
        'extensions': ['.php', '.asp'],
        'random_strings': False,
        'requests_per_second': 10,
        'duration_seconds': 20,
        'status_codes': {'200': 30, '500': 40, '404': 20, '403': 10},
    },
    
    # Network Scanner (4개)
    'nmap': {
        'user_agent': 'Nmap Scripting Engine/7.94',
        'patterns': [
            '/', '/robots.txt', '/.git/HEAD', '/server-status',
            '/xmlrpc.php', '/wp-login.php',
        ],
        'extensions': ['.php', '.html', '.txt'],
        'random_strings': False,
        'requests_per_second': 8,
        'duration_seconds': 15,
        'status_codes': {'200': 50, '404': 40, '403': 10},
    },
    'masscan': {
        'user_agent': 'masscan/1.3',
        'patterns': [
            '/', '/index.html', '/admin.html',
        ],
        'extensions': ['.html'],
        'random_strings': False,
        'requests_per_second': 5,
        'duration_seconds': 10,
        'status_codes': {'200': 60, '404': 30, '403': 10},
    },
    'zmap': {
        'user_agent': 'ZMap/4.0',
        'patterns': [
            '/', '/index.html',
        ],
        'extensions': ['.html'],
        'random_strings': False,
        'requests_per_second': 3,
        'duration_seconds': 8,
        'status_codes': {'200': 70, '404': 20, '403': 10},
    },
    'unicornscan': {
        'user_agent': 'unicornscan/0.4.7',
        'patterns': [
            '/', '/index.html', '/test.html',
        ],
        'extensions': ['.html', '.php'],
        'random_strings': False,
        'requests_per_second': 6,
        'duration_seconds': 12,
        'status_codes': {'200': 65, '404': 25, '403': 10},
    },
    
    # Attack Framework (10개)
    'metasploit': {
        'user_agent': 'Metasploit/6.3.58',
        'patterns': [
            '/exploit.php', '/shell.php', '/cmd.php', '/admin.php',
        ],
        'extensions': ['.php', '.jsp', '.asp'],
        'random_strings': False,
        'requests_per_second': 10,
        'duration_seconds': 18,
        'status_codes': {'404': 50, '403': 30, '500': 15, '200': 5},
    },
    'w3af': {
        'user_agent': 'w3af.org/2.0',
        'patterns': [
            '/index.php?id=1', '/page.php?file=../../etc/passwd',
            '/search.php?q=<script>alert(1)</script>',
        ],
        'extensions': ['.php', '.asp', '.jsp'],
        'random_strings': False,
        'requests_per_second': 22,
        'duration_seconds': 25,
        'status_codes': {'200': 40, '404': 35, '500': 15, '403': 10},
    },
    'hydra': {
        'user_agent': 'Hydra/v9.5',
        'patterns': [
            '/login.php', '/admin.php', '/auth.php', '/signin.php',
        ],
        'extensions': ['.php', '.asp', '.jsp'],
        'random_strings': False,
        'requests_per_second': 30,
        'duration_seconds': 20,
        'status_codes': {'401': 80, '200': 10, '403': 10},
    },
    'medusa': {
        'user_agent': 'Medusa/2.2',
        'patterns': [
            '/login.php', '/admin.php', '/wp-login.php',
        ],
        'extensions': ['.php'],
        'random_strings': False,
        'requests_per_second': 25,
        'duration_seconds': 18,
        'status_codes': {'401': 75, '200': 15, '403': 10},
    },
    'ncrack': {
        'user_agent': 'Ncrack/0.7',
        'patterns': [
            '/login', '/admin', '/auth',
        ],
        'extensions': ['.php', '.html'],
        'random_strings': False,
        'requests_per_second': 20,
        'duration_seconds': 15,
        'status_codes': {'401': 70, '200': 20, '403': 10},
    },
    'wpscan': {
        'user_agent': 'WPScan v3.8.25',
        'patterns': [
            '/wp-login.php', '/wp-admin/', '/xmlrpc.php', '/wp-json/',
            '/readme.html', '/license.txt',
        ],
        'extensions': ['.php', '.html', '.txt'],
        'random_strings': False,
        'requests_per_second': 28,
        'duration_seconds': 22,
        'status_codes': {'200': 50, '404': 30, '403': 20},
    },
    'joomscan': {
        'user_agent': 'Joomla! Scanner/0.0.7',
        'patterns': [
            '/administrator/', '/components/', '/modules/', '/plugins/',
            '/templates/', '/configuration.php',
        ],
        'extensions': ['.php'],
        'random_strings': False,
        'requests_per_second': 25,
        'duration_seconds': 20,
        'status_codes': {'200': 45, '404': 35, '403': 20},
    },
    'nuclei': {
        'user_agent': 'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)',
        'patterns': [
            '/.git/config', '/.env', '/admin/', '/api/', '/debug/',
        ],
        'extensions': ['.php', '.html', '.json', '.xml'],
        'random_strings': False,
        'requests_per_second': 40,
        'duration_seconds': 18,
        'status_codes': {'404': 70, '200': 20, '403': 10},
    },
    'jaeles': {
        'user_agent': 'Jaeles/v0.17',
        'patterns': [
            '/.git/', '/admin/', '/api/', '/config/', '/backup/',
        ],
        'extensions': ['.php', '.html', '.json'],
        'random_strings': False,
        'requests_per_second': 35,
        'duration_seconds': 16,
        'status_codes': {'404': 65, '200': 25, '403': 10},
    },
    'commix': {
        'user_agent': 'commix/v3.8',
        'patterns': [
            '/index.php?cmd=id', '/page.php?exec=whoami', '/view.php?command=ls',
        ],
        'extensions': ['.php', '.asp', '.jsp'],
        'random_strings': False,
        'requests_per_second': 18,
        'duration_seconds': 22,
        'status_codes': {'200': 30, '500': 40, '404': 20, '403': 10},
    },
    
    # HTTP Client (4개)
    'python-requests': {
        'user_agent': 'python-requests/2.31.0',
        'patterns': [
            '/api/users', '/api/data', '/api/status', '/health',
        ],
        'extensions': ['.json', '.xml'],
        'random_strings': False,
        'requests_per_second': 15,
        'duration_seconds': 12,
        'status_codes': {'200': 70, '404': 20, '500': 10},
    },
    'curl': {
        'user_agent': 'curl/8.4.0',
        'patterns': [
            '/', '/index.html', '/robots.txt', '/sitemap.xml',
        ],
        'extensions': ['.html', '.xml', '.txt'],
        'random_strings': False,
        'requests_per_second': 5,
        'duration_seconds': 10,
        'status_codes': {'200': 80, '404': 15, '403': 5},
    },
    'wget': {
        'user_agent': 'Wget/1.21.4',
        'patterns': [
            '/', '/index.html', '/page.html', '/document.pdf',
        ],
        'extensions': ['.html', '.pdf', '.txt', '.zip'],
        'random_strings': False,
        'requests_per_second': 4,
        'duration_seconds': 15,
        'status_codes': {'200': 75, '404': 20, '403': 5},
    },
    'python': {
        'user_agent': 'Python/3.11 urllib',
        'patterns': [
            '/api/', '/data/', '/files/', '/download/',
        ],
        'extensions': ['.json', '.xml', '.txt'],
        'random_strings': False,
        'requests_per_second': 8,
        'duration_seconds': 14,
        'status_codes': {'200': 65, '404': 25, '500': 10},
    },
}

# ============================================================================
# 더미 로그 생성 함수
# ============================================================================

def generate_random_string(length=8):
    """무작위 문자열 생성 (Nikto 스타일)"""
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(length))

def choose_status_code(distribution):
    """상태 코드 분포에 따라 선택"""
    codes = list(distribution.keys())
    weights = list(distribution.values())
    return random.choices(codes, weights=weights)[0]

def generate_uri(tool_info):
    """도구 특성에 맞는 URI 생성"""
    pattern = random.choice(tool_info['patterns'])
    
    # 무작위 8자 문자열 추가 (Nikto)
    if tool_info['random_strings'] and random.random() > 0.3:
        random_str = generate_random_string(8)
        ext = random.choice(tool_info['extensions'])
        return f"/{random_str}{ext}"
    
    # 확장자 추가
    if random.random() > 0.5 and tool_info['extensions']:
        ext = random.choice(tool_info['extensions'])
        if '?' not in pattern:
            return pattern + ext
    
    return pattern

def generate_log_entry(timestamp, ip, tool_name, tool_info):
    """IIS W3C 로그 엔트리 생성"""
    uri = generate_uri(tool_info)
    status = choose_status_code(tool_info['status_codes'])
    user_agent = tool_info['user_agent'].replace(' ', '+')
    
    # IIS W3C 형식
    # date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
    
    date_str = timestamp.strftime('%Y-%m-%d')
    time_str = timestamp.strftime('%H:%M:%S')
    method = 'GET'
    server_ip = '192.168.100.50'
    port = '80'
    client_ip = ip
    referer = '-'
    sc_substatus = '0'
    sc_win32_status = '0' if status == '200' else '2'
    time_taken = random.randint(10, 500)
    
    # URI 분리 (stem과 query)
    if '?' in uri:
        uri_stem, uri_query = uri.split('?', 1)
        # 공백을 +로 치환 (공백이 필드 구분자이므로)
        uri_query = uri_query.replace(' ', '+')
    else:
        uri_stem = uri
        uri_query = '-'
    
    return f"{date_str} {time_str} {server_ip} {method} {uri_stem} {uri_query} {port} - {client_ip} {user_agent} {referer} {status} {sc_substatus} {sc_win32_status} {time_taken}\r\n"

def generate_dummy_log(output_file='dummy_recon.log'):
    """24개 정찰 도구의 더미 로그 생성"""
    
    print(f"[*] 더미 IIS 로그 생성 중: {output_file}\n")
    
    # IIS 헤더
    header = """#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2025-11-20 00:00:00
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(header)
        
        # 시작 시간
        base_time = datetime(2025, 11, 20, 0, 0, 0)
        current_time = base_time
        
        tool_num = 0
        total_requests = 0
        
        for tool_name, tool_info in RECON_TOOLS.items():
            tool_num += 1
            
            # 각 도구마다 다른 IP 사용
            attacker_ip = f"203.0.113.{10 + tool_num}"
            
            # 도구 시작 전 5초 간격
            current_time += timedelta(seconds=5)
            
            print(f"[{tool_num}/24] {tool_name:20s} | IP: {attacker_ip:15s} | ", end='')
            
            # 요청 생성
            duration = tool_info['duration_seconds']
            req_per_sec = tool_info['requests_per_second']
            total_tool_requests = duration * req_per_sec
            
            for i in range(total_tool_requests):
                # 시간 계산 (균등 분포)
                offset_seconds = (i / req_per_sec)
                request_time = current_time + timedelta(seconds=offset_seconds)
                
                # 로그 엔트리 생성
                log_entry = generate_log_entry(request_time, attacker_ip, tool_name, tool_info)
                f.write(log_entry)
            
            total_requests += total_tool_requests
            
            # 도구 종료 시간 업데이트
            current_time += timedelta(seconds=duration)
            
            print(f"{total_tool_requests:5d} 요청 | {duration:2d}초 | {req_per_sec:3d} req/s")
    
    print(f"\n[+] 완료!")
    print(f"    총 도구: 24개")
    print(f"    총 요청: {total_requests:,}개")
    print(f"    파일 크기: ", end='')
    
    # 파일 크기 확인
    import os
    file_size = os.path.getsize(output_file)
    if file_size > 1024*1024:
        print(f"{file_size/(1024*1024):.2f} MB")
    else:
        print(f"{file_size/1024:.2f} KB")
    
    print(f"    저장 위치: {output_file}")

# ============================================================================
# 메인 함수
# ============================================================================

def main():
    import sys
    
    output_file = 'dummy_recon.log'
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    
    print("=" * 80)
    print("더미 IIS 로그 생성기 - 24개 정찰 도구 시뮬레이션")
    print("=" * 80)
    print()
    
    generate_dummy_log(output_file)
    
    print("\n[*] 다음 명령어로 분석하세요:")
    print(f"    python recon_tool_detector_v2.py {output_file}")

if __name__ == '__main__':
    main()
