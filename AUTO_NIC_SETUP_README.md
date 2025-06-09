# 자동 NIC 설정 시스템

이 시스템은 새로운 네트워크 인터페이스(NIC)가 감지되면 자동으로 DHCP를 통해 IP를 할당받고, Policy-Based Routing(PBR) 규칙을 업데이트하는 자동화 시스템입니다.

## 구성 요소

### 1. udev 규칙
- **파일**: `/etc/udev/rules.d/99-auto-nic-setup.rules`
- **기능**: 새로운 네트워크 인터페이스가 추가되거나 활성화될 때 자동으로 스크립트 실행
- **지원 인터페이스**: ens*, eth*, enp*

### 2. 자동 설정 스크립트
- **파일**: `/usr/local/bin/auto-nic-setup.sh`
- **기능**: 
  - 인터페이스 상태 확인
  - DHCP를 통한 IP 할당
  - Policy Routing 규칙 자동 업데이트
  - 상세한 로깅

### 3. NetworkManager Dispatcher
- **파일**: `/etc/NetworkManager/dispatcher.d/99-policy-routing`
- **기능**: NetworkManager에서 인터페이스가 up 상태가 될 때 추가적으로 스크립트 실행

### 4. 로그 파일
- **파일**: `/var/log/auto-nic-setup.log`
- **기능**: 모든 자동화 작업의 상세 로그 기록

## 동작 방식

1. **NIC 감지**: 새로운 NIC가 시스템에 추가되면 udev 규칙이 트리거됨
2. **자동 활성화**: 인터페이스가 DOWN 상태면 자동으로 UP 상태로 변경
3. **DHCP 설정**: dhclient를 사용하여 자동으로 IP 주소 할당 시도
4. **PBR 업데이트**: IP 할당이 성공하면 policy_routing.py의 apply_changes 실행
5. **로깅**: 모든 과정이 `/var/log/auto-nic-setup.log`에 기록됨

## 현재 설정된 인터페이스

```bash
# 현재 PBR 규칙 확인
ip rule show

# 현재 라우팅 테이블 확인
ip route show table nic1
ip route show table nic2
ip route show table nic3

# 로그 확인
sudo tail -f /var/log/auto-nic-setup.log
```

## 수동 테스트

새로운 NIC가 추가되었을 때 수동으로 테스트하려면:

```bash
# 수동으로 스크립트 실행
sudo /usr/local/bin/auto-nic-setup.sh ens9

# 또는 udev 이벤트 시뮬레이션
sudo udevadm trigger --subsystem-match=net --action=add
```

## 문제 해결

### 로그 확인
```bash
sudo tail -n 50 /var/log/auto-nic-setup.log
```

### udev 규칙 다시 로드
```bash
sudo udevadm control --reload-rules
```

### 수동으로 PBR 규칙 적용
```bash
cd /home/pieroot/policy-routing
sudo python3 policy_routing.py apply_changes
```

## 주의사항

- 이 시스템은 물리적 네트워크 인터페이스(ens*, eth*, enp*)에만 적용됩니다
- 가상 인터페이스(docker*, veth*, br-*)는 자동으로 제외됩니다
- DHCP 서버가 있는 네트워크에서만 정상 동작합니다
- 시스템 부팅 시에도 자동으로 적용됩니다

## 설치된 파일 목록

- `/usr/local/bin/auto-nic-setup.sh` - 메인 자동화 스크립트
- `/etc/udev/rules.d/99-auto-nic-setup.rules` - udev 규칙
- `/etc/NetworkManager/dispatcher.d/99-policy-routing` - NetworkManager dispatcher
- `/var/log/auto-nic-setup.log` - 로그 파일
