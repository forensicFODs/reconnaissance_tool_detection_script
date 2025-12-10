| 초기 정찰 도구 리스트 | 도구 |
| --- | --- |
| **디렉토리 브루트포스 도구 (7개)** | ✅ **Nikto** - 웹 서버 취약점 스캐너
✅ **Gobuster** - Go 기반 빠른 브루트포서
✅ **DirBuster** - OWASP 디렉토리 스캐너
✅ **Dirb** - URL 브루트포서
✅ **wfuzz** - 웹 퍼저
✅ **ffuf** - Fast web fuzzer
✅ **Feroxbuster** - Rust 기반 브루트포서 |
| **웹 취약점 스캐너 (6개)** | ✅ **Arachni** - 루비 기반 보안 스캐너
✅ **OWASP ZAP** - 오픈소스 침투 테스트 도구
✅ **Burp Suite** - 상용 웹 보안 도구
✅ **Acunetix** - 상용 취약점 스캐너
✅ **Nessus** - 네트워크 취약점 스캐너
✅ **OpenVAS** - 오픈소스 취약점 스캐너 |
| **SQL Injection 도구 (3개)** | ✅ **SQLMap** - 자동 SQL Injection
✅ **Havij** - GUI SQLi 도구
✅ **Pangolin** - SQLi 도구 |
| **네트워크 스캐너 (4개)** | ✅ **Nmap** - 네트워크 매핑
✅ **Masscan** - 고속 포트 스캐너
✅ **ZMap** - 인터넷 스캐너
✅ **Unicornscan** - 비동기 스캐너 |
| **기타 공격 도구 (4개)** | ✅ **Metasploit** - 익스플로잇 프레임워크
✅ **Hydra, Medusa, Ncrack** - 패스워드 브루트포스
✅ **WPScan, JoomScan** - CMS 스캐너
✅ **Nuclei, Jaeles** - 자동화 스캐너 |
| **스크립팅 도구** | ✅ **Python-requests, curl, wget** - HTTP 클라이언트 |

---

> **포렌식 관점에서 Mixed logs를 Unified Timeline CSV로 변환하는 Python 스크립트**
> 

<aside>

💡 요구사항

1. 다양한 형식의 로그 파싱 (Apache, Nginx, IIS, 시스템 로그 등)
2. 중복 제거 알고리즘
3. 이벤트 그룹화 및 요약
4. 포렌식 분석에 필요한 필드 추출
5. 시간 정규화 및 타임라인 생성

[README.md](attachment:8b99ab41-23fb-47cc-881b-16dd98617d52:README.md)

</aside>

- 탐지 툴
    
    
- cmd 명령어
    
    ```bash
    python recon_tool_detector.py u_ex251112.log
    ```
    
- 실행 결과
    
    ![image.png](attachment:1f81ca96-4a00-4ff4-9478-ef2a41ce111f:image.png)
    
    [u_ex251112_recon_report.md](attachment:e7695e3e-05ee-4a45-af42-889679645aea:u_ex251112_recon_report.md)
    

---

**이 밖에 다른 더미 파일로 다 탐지 되는 지 확인**

1. **recon_tool_detector_v2.py** (22KB)
 
    
    - 24개 도구 탐지
    - User-Agent + 행동 패턴 이중 탐지
    - 자동 그룹화
    - CSV + 마크다운 보고서 생성
    - **JoomScan 패턴 수정** (Joomla! Scanner 대응)
2. **generate_dummy_log.py** (20KB)
    
    - 24개 정찰 도구 시뮬레이션
    - IIS W3C 로그 형식
    - 도구별 실제 행동 패턴 구현
    - 커스터마이징 가능
    
    
3. 실행 코드
    
    ```bash
    python generate_dummy_log.py dummy_test.log
    ```
    
4. 실행 결과
    
    [dummy_test_recon_report.md](attachment:0cb69ed4-7c13-48dc-b973-b19effaf2886:dummy_test_recon_report.md)
    
    [dummy_test_recon_tools.csv](attachment:fb0b7a7d-7c34-469b-897e-355d9e3ecb3e:dummy_test_recon_tools.csv)
