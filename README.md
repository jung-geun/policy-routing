# Policy Routing

이 프로젝트는 정책 기반 라우팅을 구현하기 위한 Python 스크립트입니다. 이 스크립트는 특정 IP 주소에 대해 지정된 게이트웨이를 사용하여 패킷을 라우팅합니다.

사전 조건으로는 `iproute2` 패키지가 설치되어 있어야 하며, 이 패키지는 Linux 시스템에서 네트워크 인터페이스와 라우팅 테이블을 관리하는 데 사용됩니다.
NIC 의 ip 설정이 미리 되어 있어야 합니다.

## 기능

- 특정 IP 주소에 대해 지정된 게이트웨이를 사용하여 패킷 라우팅
- 라우팅 테이블을 생성하고, 해당 테이블에 규칙을 추가하여 정책 기반 라우팅을 구현
- 자동으로 NIC를 검색하고, 해당 NIC에 대한 라우팅 테이블을 설정

# 사용 방법

스크립트는 아래 명령어로 다운로드 받을 수 있습니다

```bash
wget -O policy_routing.py https://git.dmslab.xyz/dmslab/policy-routing/-/raw/main/policy_routing.py
# or
curl -o policy_routing.py https://git.dmslab.xyz/dmslab/policy-routing/-/raw/main/policy_routing.py
```
