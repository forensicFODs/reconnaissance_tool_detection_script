#!/usr/bin/env python3
"""
고급 정찰 도구 탐지기 v2 (행동 패턴 + User-Agent)
- User-Agent 기반 탐지
- 행동 패턴 기반 추정 (위장 대응)
- 유사 도구 자동 그룹화
- 마크다운 보고서 자동 생성
"""

import re
import csv
from collections import defaultdict
from urllib.parse import unquote
from datetime import datetime

# ============================================================================
# 도구 시그니처 정의
# ============================================================================

TOOL_SIGNATURES = {
    'Directory Bruteforce': {
        'nikto': {'pattern': r'nikto[/\s]*([\d\.]+)?', 'name': 'Nikto', 'desc': '웹 서버 취약점 스캐너'},
        'gobuster': {'pattern': r'gobuster[/\s]*([\d\.]+)?', 'name': 'Gobuster', 'desc': 'Go 기반 빠른 브루트포서'},
        'dirbuster': {'pattern': r'dirbuster[/\s]*([\d\.]+)?', 'name': 'DirBuster', 'desc': 'OWASP 디렉토리 스캐너'},
        'dirb': {'pattern': r'dirb[/\s]*([\d\.]+)?', 'name': 'Dirb', 'desc': 'URL 브루트포서'},
        'wfuzz': {'pattern': r'wfuzz[/\s]*([\d\.]+)?', 'name': 'wfuzz', 'desc': '웹 퍼저'},
        'ffuf': {'pattern': r'ffuf[/\s]*([\d\.]+)?', 'name': 'ffuf', 'desc': 'Fast web fuzzer'},
        'feroxbuster': {'pattern': r'feroxbuster[/\s]*([\d\.]+)?', 'name': 'Feroxbuster', 'desc': 'Rust 기반 브루트포서'},
    },
    'Web Vulnerability Scanner': {
        'arachni': {'pattern': r'arachni[/\s]*([\d\.]+)?', 'name': 'Arachni', 'desc': '루비 기반 보안 스캐너'},
        'zap': {'pattern': r'(?:owasp[- ]?)?zap[/\s]*([\d\.]+)?', 'name': 'OWASP ZAP', 'desc': '오픈소스 침투 테스트 도구'},
        'burp': {'pattern': r'burp[- ]?suite[/\s]*([\d\.]+)?', 'name': 'Burp Suite', 'desc': '상용 웹 보안 도구'},
        'acunetix': {'pattern': r'acunetix[/\s]*([\d\.]+)?', 'name': 'Acunetix', 'desc': '상용 취약점 스캐너'},
        'nessus': {'pattern': r'nessus[/\s]*([\d\.]+)?', 'name': 'Nessus', 'desc': '네트워크 취약점 스캐너'},
        'openvas': {'pattern': r'openvas[/\s]*([\d\.]+)?', 'name': 'OpenVAS', 'desc': '오픈소스 취약점 스캐너'},
    },
    'SQL Injection Tool': {
        'sqlmap': {'pattern': r'sqlmap[/\s]*([\d\.]+)?', 'name': 'SQLMap', 'desc': '자동 SQL Injection 도구'},
        'havij': {'pattern': r'havij[/\s]*([\d\.]+)?', 'name': 'Havij', 'desc': 'GUI SQL Injection 도구'},
        'pangolin': {'pattern': r'pangolin[/\s]*([\d\.]+)?', 'name': 'Pangolin', 'desc': 'SQL Injection 도구'},
    },
    'Network Scanner': {
        'nmap': {'pattern': r'nmap[/\s]*([\d\.]+)?', 'name': 'Nmap', 'desc': '네트워크 매핑 도구'},
        'masscan': {'pattern': r'masscan[/\s]*([\d\.]+)?', 'name': 'Masscan', 'desc': '고속 포트 스캐너'},
        'zmap': {'pattern': r'zmap[/\s]*([\d\.]+)?', 'name': 'ZMap', 'desc': '인터넷 스캐너'},
        'unicornscan': {'pattern': r'unicornscan[/\s]*([\d\.]+)?', 'name': 'Unicornscan', 'desc': '비동기 포트 스캐너'},
    },
    'Attack Framework': {
        'metasploit': {'pattern': r'metasploit[/\s]*([\d\.]+)?', 'name': 'Metasploit', 'desc': '익스플로잇 프레임워크'},
        'w3af': {'pattern': r'w3af[/\s]*([\d\.]+)?', 'name': 'w3af', 'desc': '웹 공격 프레임워크'},
        'hydra': {'pattern': r'hydra[/\s]*([\d\.]+)?', 'name': 'Hydra', 'desc': '패스워드 브루트포스'},
        'medusa': {'pattern': r'medusa[/\s]*([\d\.]+)?', 'name': 'Medusa', 'desc': '패스워드 브루트포스'},
        'ncrack': {'pattern': r'ncrack[/\s]*([\d\.]+)?', 'name': 'Ncrack', 'desc': '네트워크 인증 크래킹'},
        'wpscan': {'pattern': r'wpscan[/\s]*([\d\.]+)?', 'name': 'WPScan', 'desc': 'WordPress 스캐너'},
        'joomscan': {'pattern': r'joomscan[/\s]*([\d\.]+)?', 'name': 'JoomScan', 'desc': 'Joomla 스캐너'},
        'nuclei': {'pattern': r'nuclei[/\s]*([\d\.]+)?', 'name': 'Nuclei', 'desc': '자동화 취약점 스캐너'},
        'jaeles': {'pattern': r'jaeles[/\s]*([\d\.]+)?', 'name': 'Jaeles', 'desc': '자동화 스캐너'},
        'commix': {'pattern': r'commix[/\s]*([\d\.]+)?', 'name': 'Commix', 'desc': 'Command Injection 도구'},
    },
    'HTTP Client': {
        'python-requests': {'pattern': r'python[- ]requests[/\s]*([\d\.]+)?', 'name': 'Python-Requests', 'desc': 'Python HTTP 라이브러리'},
        'curl': {'pattern': r'curl[/\s]*([\d\.]+)?', 'name': 'cURL', 'desc': 'HTTP 클라이언트'},
        'wget': {'pattern': r'wget[/\s]*([\d\.]+)?', 'name': 'Wget', 'desc': 'HTTP 다운로더'},
        'python': {'pattern': r'python[/\s]*([\d\.]+)?', 'name': 'Python Script', 'desc': 'Python 기반 스크립트'},
    },
}

# ============================================================================
# 행동 패턴 기반 도구 추정
# ============================================================================

def estimate_tool_by_behavior(data):
    """행동 패턴으로 도구 추정"""
    
    total = len(data['timestamps'])
    extensions = data['extensions']
    uris = data['uris']
    status_codes = data['status_codes']
    
    # 무작위 8자 문자열 패턴 (Nikto 시그니처)
    random_8char = sum(1 for uri in uris if re.search(r'/[a-zA-Z0-9]{8}(?:\.|/|$)', uri))
    
    # 404 비율
    status_404 = status_codes.get('404', 0)
    ratio_404 = status_404 / total if total > 0 else 0
    
    # 디버깅
    # print(f"DEBUG: total={total}, random={random_8char}, ext={len(extensions)}, 404={ratio_404:.2f}")
    
    # SQL Injection 패턴
    sql_patterns = ['union', 'select', 'sleep(', 'benchmark', 'waitfor', "' or ", '" or ']
    sql_count = sum(1 for uri in uris if any(p in uri.lower() for p in sql_patterns))
    
    # 민감 경로
    sensitive = ['/admin', '/config', '/backup', '/.git', '/.svn', '/phpmyadmin']
    sensitive_count = sum(1 for uri in uris if any(p in uri.lower() for p in sensitive))
    
    # 도구 추정
    estimations = []
    
    # Nikto/DirBuster 패턴 (무작위 8자 문자열 + 대량 확장자 + 높은 404)
    if random_8char > 100 and len(extensions) > 100 and ratio_404 > 0.9:
        estimations.append({
            'category': 'Directory Bruteforce',
            'tool_name': 'Nikto/DirBuster (추정)',
            'tool_version': 'Unknown',
            'desc': '웹 서버 취약점 스캐너 (행동 패턴 기반 추정)',
            'confidence': 95,
            'detection_method': 'Behavior Pattern',
            'evidence': f'무작위 문자열 {random_8char}개, 확장자 {len(extensions)}종류, 404 비율 {ratio_404*100:.1f}%',
        })
    
    # SQLMap 패턴
    elif sql_count > 50:
        estimations.append({
            'category': 'SQL Injection Tool',
            'tool_name': 'SQLMap (추정)',
            'tool_version': 'Unknown',
            'desc': 'SQL Injection 자동화 도구 (행동 패턴 기반 추정)',
            'confidence': 85,
            'detection_method': 'Behavior Pattern',
            'evidence': f'SQL Injection 시도 {sql_count}개',
        })
    
    # 일반 디렉토리 브루트포스
    elif total > 1000 and len(extensions) > 30 and ratio_404 > 0.7:
        estimations.append({
            'category': 'Directory Bruteforce',
            'tool_name': 'Directory Scanner (추정)',
            'tool_version': 'Unknown',
            'desc': '디렉토리 브루트포스 도구 (행동 패턴 기반 추정)',
            'confidence': 70,
            'detection_method': 'Behavior Pattern',
            'evidence': f'대량 요청 {total}개, 확장자 {len(extensions)}종류, 404 비율 {ratio_404*100:.1f}%',
        })
    
    return estimations

# ============================================================================
# User-Agent 기반 도구 탐지
# ============================================================================

def detect_tool_from_ua(user_agent):
    """User-Agent에서 도구 탐지"""
    ua_lower = user_agent.lower() if user_agent else ''
    
    detected = []
    
    for category, tools in TOOL_SIGNATURES.items():
        for tool_key, tool_info in tools.items():
            match = re.search(tool_info['pattern'], ua_lower, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex and match.group(1) else 'Unknown'
                detected.append({
                    'category': category,
                    'tool_name': tool_info['name'],
                    'tool_version': version,
                    'desc': tool_info['desc'],
                    'confidence': 100,
                    'detection_method': 'User-Agent',
                    'evidence': f'User-Agent: {user_agent[:60]}',
                })
                break  # 같은 카테고리에서 하나만
    
    return detected

# ============================================================================
# 로그 분석
# ============================================================================

def analyze_iis_log(log_file):
    """IIS 로그 분석"""
    
    print(f"[*] IIS 로그 분석 중: {log_file}\n")
    
    session_stats = defaultdict(lambda: {
        'timestamps': [],
        'uris': [],
        'status_codes': defaultdict(int),
        'extensions': set(),
        'user_agent': None,
    })
    
    line_count = 0
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            
            line_count += 1
            parts = line.strip().split()
            
            if len(parts) < 14:
                continue
            
            date = parts[0]
            time_str = parts[1]
            client_ip = parts[8]
            uri = parts[4]
            status = parts[11]  # sc-status는 12번째 필드 (index 11)
            user_agent = unquote(parts[9].replace('+', ' '))
            
            try:
                timestamp = datetime.strptime(f"{date} {time_str}", "%Y-%m-%d %H:%M:%S")
            except:
                continue
            
            key = (client_ip, user_agent)
            
            session_stats[key]['timestamps'].append(timestamp)
            session_stats[key]['uris'].append(uri)
            session_stats[key]['status_codes'][status] += 1
            session_stats[key]['user_agent'] = user_agent
            
            if '.' in uri.split('/')[-1]:
                ext = uri.split('/')[-1].split('.')[-1].split('?')[0]
                if ext and len(ext) < 10:
                    session_stats[key]['extensions'].add(ext)
    
    print(f"[+] {line_count:,}개 로그 라인 분석")
    print(f"[+] {len(session_stats)}개 세션 발견\n")
    
    # 도구 탐지
    detected_tools = defaultdict(list)
    
    for (ip, user_agent), data in session_stats.items():
        if len(data['timestamps']) < 10:
            continue
        
        # 1. User-Agent 기반 탐지
        ua_tools = detect_tool_from_ua(user_agent)
        
        # 2. 행동 패턴 기반 추정 (User-Agent에서 탐지 못한 경우만)
        behavior_tools = []
        if not ua_tools:
            behavior_tools = estimate_tool_by_behavior(data)
        
        # 통합
        all_tools = ua_tools + behavior_tools
        
        if not all_tools:
            continue
        
        # 통계 계산
        timestamps = sorted(data['timestamps'])
        start_time = timestamps[0]
        end_time = timestamps[-1]
        duration = (end_time - start_time).total_seconds()
        total_requests = len(timestamps)
        req_per_sec = total_requests / duration if duration > 0 else total_requests
        
        status_404 = data['status_codes'].get('404', 0)
        ratio_404 = status_404 / total_requests * 100 if total_requests > 0 else 0
        
        for tool in all_tools:
            detected_tools[tool['category']].append({
                'ip': ip,
                'tool_name': tool['tool_name'],
                'tool_version': tool['tool_version'],
                'description': tool['desc'],
                'confidence': tool['confidence'],
                'detection_method': tool['detection_method'],
                'evidence': tool['evidence'],
                'start_time': start_time,
                'end_time': end_time,
                'duration': duration,
                'total_requests': total_requests,
                'req_per_sec': req_per_sec,
                'unique_extensions': len(data['extensions']),
                'status_404': status_404,
                'ratio_404': ratio_404,
                'user_agent': user_agent[:100],
            })
    
    return detected_tools

# ============================================================================
# 출력 함수들
# ============================================================================

def print_grouped_results(detected_tools):
    """그룹화된 결과 출력"""
    
    print("=" * 100)
    print("초기 정찰 도구 탐지 결과 (카테고리별 그룹화)")
    print("=" * 100)
    
    if not detected_tools:
        print("\n[!] 탐지된 정찰 도구가 없습니다.")
        return
    
    category_order = [
        'Directory Bruteforce',
        'Web Vulnerability Scanner',
        'SQL Injection Tool',
        'Network Scanner',
        'Attack Framework',
        'HTTP Client',
    ]
    
    total_tools = 0
    
    for category in category_order:
        if category not in detected_tools:
            continue
        
        tools = detected_tools[category]
        total_tools += len(tools)
        
        print(f"\n{'='*100}")
        print(f"📁 {category} ({len(tools)}개 탐지)")
        print(f"{'='*100}")
        
        for i, tool in enumerate(sorted(tools, key=lambda x: x['start_time']), 1):
            version_str = f"v{tool['tool_version']}" if tool['tool_version'] != 'Unknown' else ''
            
            print(f"\n[{i}] {tool['tool_name']} {version_str}")
            print(f"  설명: {tool['description']}")
            print(f"  탐지 방법: {tool['detection_method']} (신뢰도 {tool['confidence']}%)")
            print(f"  증거: {tool['evidence']}")
            print(f"  IP 주소: {tool['ip']}")
            print(f"  활동 시간: {tool['start_time'].strftime('%Y-%m-%d %H:%M:%S')} ~ {tool['end_time'].strftime('%H:%M:%S')}")
            print(f"  지속 시간: {tool['duration']:.1f}초")
            print(f"  총 요청: {tool['total_requests']:,}개 ({tool['req_per_sec']:.1f} req/s)")
            print(f"  확장자 종류: {tool['unique_extensions']}개")
            print(f"  404 에러: {tool['status_404']:,}개 ({tool['ratio_404']:.1f}%)")
    
    print(f"\n{'='*100}")
    print(f"총 {total_tools}개 정찰 도구 탐지 ({len(detected_tools)}개 카테고리)")
    print(f"{'='*100}")

def save_csv(detected_tools, output_file):
    """CSV 저장"""
    
    print(f"\n[*] CSV 저장 중: {output_file}")
    
    all_tools = []
    for category, tools in detected_tools.items():
        for tool in tools:
            tool['category'] = category
            all_tools.append(tool)
    
    all_tools.sort(key=lambda x: x['start_time'])
    
    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        fieldnames = [
            'category', 'tool_name', 'tool_version', 'description', 'confidence',
            'detection_method', 'evidence', 'ip_address', 'start_time', 'end_time',
            'duration_seconds', 'total_requests', 'requests_per_second',
            'unique_extensions', 'status_404', '404_ratio_percent', 'user_agent'
        ]
        
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for tool in all_tools:
            writer.writerow({
                'category': tool['category'],
                'tool_name': tool['tool_name'],
                'tool_version': tool['tool_version'],
                'description': tool['description'],
                'confidence': tool['confidence'],
                'detection_method': tool['detection_method'],
                'evidence': tool['evidence'],
                'ip_address': tool['ip'],
                'start_time': tool['start_time'].strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': tool['end_time'].strftime('%Y-%m-%d %H:%M:%S'),
                'duration_seconds': f"{tool['duration']:.1f}",
                'total_requests': tool['total_requests'],
                'requests_per_second': f"{tool['req_per_sec']:.1f}",
                'unique_extensions': tool['unique_extensions'],
                'status_404': tool['status_404'],
                '404_ratio_percent': f"{tool['ratio_404']:.1f}",
                'user_agent': tool['user_agent'],
            })
    
    print(f"[+] 저장 완료: {output_file}")

def generate_markdown_report(detected_tools, output_file):
    """마크다운 보고서 생성"""
    
    print(f"[*] 마크다운 보고서 생성 중: {output_file}")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# 🔍 초기 정찰 도구 탐지 보고서\n\n")
        f.write(f"**생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        
        if not detected_tools:
            f.write("## ⚠️ 탐지 결과 없음\n\n정찰 도구가 탐지되지 않았습니다.\n")
            return
        
        # 요약
        total_tools = sum(len(tools) for tools in detected_tools.values())
        f.write("## 📊 탐지 요약\n\n")
        f.write(f"- **총 탐지 도구:** {total_tools}개\n")
        f.write(f"- **탐지 카테고리:** {len(detected_tools)}개\n\n")
        
        f.write("| 카테고리 | 탐지 수 |\n|----------|--------|\n")
        for category, tools in detected_tools.items():
            f.write(f"| {category} | {len(tools)}개 |\n")
        
        f.write("\n---\n\n")
        
        # 카테고리별 상세
        category_order = [
            'Directory Bruteforce', 'Web Vulnerability Scanner', 'SQL Injection Tool',
            'Network Scanner', 'Attack Framework', 'HTTP Client',
        ]
        
        for category in category_order:
            if category not in detected_tools:
                continue
            
            tools = detected_tools[category]
            f.write(f"## 📁 {category}\n\n**탐지 수:** {len(tools)}개\n\n")
            
            for i, tool in enumerate(sorted(tools, key=lambda x: x['start_time']), 1):
                version_str = f" v{tool['tool_version']}" if tool['tool_version'] != 'Unknown' else ''
                
                f.write(f"### {i}. {tool['tool_name']}{version_str}\n\n")
                f.write(f"- **설명:** {tool['description']}\n")
                f.write(f"- **탐지 방법:** {tool['detection_method']} (신뢰도 {tool['confidence']}%)\n")
                f.write(f"- **증거:** {tool['evidence']}\n")
                f.write(f"- **IP 주소:** `{tool['ip']}`\n")
                f.write(f"- **활동 시간:** {tool['start_time'].strftime('%Y-%m-%d %H:%M:%S')} ~ {tool['end_time'].strftime('%H:%M:%S')}\n")
                f.write(f"- **지속 시간:** {tool['duration']:.1f}초\n")
                f.write(f"- **총 요청:** {tool['total_requests']:,}개 ({tool['req_per_sec']:.1f} req/s)\n")
                f.write(f"- **확장자 종류:** {tool['unique_extensions']}개\n")
                f.write(f"- **404 에러:** {tool['status_404']:,}개 ({tool['ratio_404']:.1f}%)\n\n")
            
            f.write("---\n\n")
        
        # 타임라인
        f.write("## 📅 공격 타임라인\n\n")
        all_tools = []
        for tools in detected_tools.values():
            all_tools.extend(tools)
        all_tools.sort(key=lambda x: x['start_time'])
        
        f.write("| 시간 | 도구 | 카테고리 | 요청 수 |\n|------|------|----------|--------|\n")
        for tool in all_tools:
            version_str = f" v{tool['tool_version']}" if tool['tool_version'] != 'Unknown' else ''
            time_range = f"{tool['start_time'].strftime('%H:%M:%S')} ~ {tool['end_time'].strftime('%H:%M:%S')}"
            f.write(f"| {time_range} | {tool['tool_name']}{version_str} | {tool['category']} | {tool['total_requests']:,}개 |\n")
    
    print(f"[+] 마크다운 보고서 저장 완료: {output_file}")

# ============================================================================
# 메인 함수
# ============================================================================

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("사용법: python recon_tool_detector_v2.py <iis_log_file>")
        print("예제: python recon_tool_detector_v2.py u_ex251112.log")
        sys.exit(1)
    
    log_file = sys.argv[1]
    output_csv = log_file.replace('.log', '_recon_tools.csv')
    output_md = log_file.replace('.log', '_recon_report.md')
    
    try:
        detected_tools = analyze_iis_log(log_file)
        print_grouped_results(detected_tools)
        
        if detected_tools:
            save_csv(detected_tools, output_csv)
            generate_markdown_report(detected_tools, output_md)
        
    except FileNotFoundError:
        print(f"[!] 파일을 찾을 수 없습니다: {log_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] 오류 발생: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
