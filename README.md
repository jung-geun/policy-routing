# Policy Routing

이 프로젝트는 정책 기반 라우팅을 구현하기 위한 Python 스크립트입니다. 이 스크립트는 특정 IP 주소에 대해 지정된 게이트웨이를 사용하여 패킷을 라우팅합니다.

사전 조건으로는 `iproute2` 패키지가 설치되어 있어야 하며, 이 패키지는 Linux 시스템에서 네트워크 인터페이스와 라우팅 테이블을 관리하는 데 사용됩니다.
NIC 의 ip 설정이 미리 되어 있어야 합니다.

## 기능

- 특정 IP 주소에 대해 지정된 게이트웨이를 사용하여 패킷 라우팅
- 라우팅 테이블을 생성하고, 해당 테이블에 규칙을 추가하여 정책 기반 라우팅을 구현
- 자동으로 NIC를 검색하고, 해당 NIC에 대한 라우팅 테이블을 설정

# 사용 방법

## 로컬에 자동 PBR 시스템 구성

스크립트는 아래 명령어로 다운로드 받을 수 있습니다

```bash
wget -O policy_routing.py https://raw.githubusercontent.com/jung-geun/policy-routing/main/policy_routing.py
# or
curl -o policy_routing.py https://raw.githubusercontent.com/jung-geun/policy-routing/main/policy_routing.py
```

다운로드한 스크립트를 setup 옵션으로 시스템 데몬으로 설치할 수 있습니다

```bash
sudo python3 policy_routing.py setup
```

ip rule 을 확인하여 정책 기반 라우팅이 설정되었는지 확인할 수 있습니다.

```bash
ip rule ls
```

## packer 를 사용하여 이미지 배포

openstack 에 자동으로 PBR 시스템을 구성하는 packer template 을 제공합니다.

### Packer 설치

https://developer.hashicorp.com/packer/tutorials/docker-get-started/get-started-install-cli

### Packer OpenStack plugin 설치

openstack 에서 사용할 수 있게 하려면 Packer OpenStack 플러그인을 설치해야 합니다. 아래 명령어를 사용하여 설치할 수 있습니다.

```bash
packer plugins install github.com/hashicorp/openstack
```

### Packer OpenStack 템플릿 설정

packer 를 사용하기 전에 openrc를 설정해야합니다

```bash
vi admin-openrc
```

설정 파일 내용은 아래 내용들을 채워야합니다.

```bash
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_NAME=admin
export OS_TENANT_NAME=$OS_PROJECT_NAME
export OS_USERNAME=admin
export OS_PASSWORD=ADMIN_PASSWORD
export OS_AUTH_URL=http://OPENSTACK_KEYSTONE_HOST/v3
export OS_IDENTITY_API_VERSION=3
export OS_IMAGE_API_VERSION=2
export OS_SOURCE_IMAGE_ID=원본_이미지_ID
export OS_NETWORK_NAME=이미지_빌드에_사용할_네트워크_ID
export OS_FLOATING_IP_POOL=플로팅_IP_풀_이름
```

위 환경 변수들은 실제 환경에 맞게 수정해야 합니다. 예를 들어, `ADMIN_PASSWORD`는 OpenStack 관리자의 비밀번호로 설정해야 하며, `OPENSTACK_KEYSTONE_HOST`는 OpenStack Keystone 서비스의 호스트 주소로 설정해야 합니다.

```bash
source admin-openrc
```

packer 를 실행할 수 있는지 확인합니다.

```bash
packer validate packer-openstack-ubuntu.json
```

### Packer OpenStack 템플릿 실행

```bash
packer build packer-openstack-ubuntu.json
```
