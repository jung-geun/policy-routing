#!/usr/bin/env python3
"""
Ubuntu 22.04 Multi-NIC Policy Based Routing Setup Script
Python Implementation
"""

import subprocess
import logging
import os
import sys
import json
import re
import ipaddress
import time
import threading
from datetime import datetime
from pathlib import Path


class PolicyBasedRoutingManager:
    def __init__(self):
        # 로깅 설정
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger(__name__)

        # 권한 확인
        if os.geteuid() != 0:
            self.logger.error("이 스크립트는 root 권한으로 실행해야 합니다.")
            sys.exit(1)

        # 네트워크 인터페이스 자동 감지
        self.config = self.auto_detect_network_config()

    def run_command(self, cmd, ignore_error=False):
        """시스템 명령어 실행"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0 and not ignore_error:
                self.logger.warning(f"명령어 실행 경고: {cmd}")
                self.logger.warning(f"오류: {result.stderr}")
            return result
        except Exception as e:
            self.logger.error(f"명령어 실행 실패: {cmd} - {e}")
            return None

    def get_network_interfaces(self):
        """활성화된 네트워크 인터페이스 목록 가져오기"""
        interfaces = {}

        # ip link show로 인터페이스 목록 가져오기
        result = self.run_command("ip link show")
        if not result or result.returncode != 0:
            self.logger.error("네트워크 인터페이스를 가져올 수 없습니다")
            return interfaces

        # 루프백과 가상 인터페이스 제외하고 물리적 인터페이스만 선택
        for line in result.stdout.split("\n"):
            match = re.match(r"^\d+:\s+(\w+):", line)
            if match:
                interface = match.group(1)
                # 루프백, docker, 가상 인터페이스 제외
                if (
                    interface != "lo"
                    and not interface.startswith("docker")
                    and not interface.startswith("veth")
                    and not interface.startswith("br-")
                    and "state UP" in line
                ):
                    interfaces[interface] = {}

        return interfaces

    def get_interface_ip_info(self, interface):
        """특정 인터페이스의 IP 정보 가져오기"""
        result = self.run_command(f"ip addr show {interface}")
        if not result or result.returncode != 0:
            return None

        ip_info = {}
        for line in result.stdout.split("\n"):
            # IPv4 주소 찾기
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if match:
                ip_addr = match.group(1)
                prefix = int(match.group(2))

                # 네트워크 주소 계산
                network = ipaddress.IPv4Network(f"{ip_addr}/{prefix}", strict=False)

                ip_info = {
                    "ip": ip_addr,
                    "prefix": prefix,
                    "network": str(network),
                    "netmask": str(network.netmask),
                }
                break

        return ip_info

    def get_default_gateway(self, interface):
        """특정 인터페이스의 기본 게이트웨이 찾기"""
        # 현재 라우팅 테이블에서 해당 인터페이스의 기본 라우트 찾기
        result = self.run_command(f"ip route show dev {interface}")
        if not result or result.returncode != 0:
            return None

        for line in result.stdout.split("\n"):
            if "default via" in line:
                match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    return match.group(1)

        # 기본 라우트가 없으면 네트워크의 첫 번째 주소(.1)를 게이트웨이로 추정
        ip_info = self.get_interface_ip_info(interface)
        if ip_info:
            network = ipaddress.IPv4Network(ip_info["network"])
            # 일반적으로 .1이 게이트웨이
            gateway = str(network.network_address + 1)
            return gateway

        return None

    def auto_detect_network_config(self):
        """네트워크 설정 자동 감지"""
        self.logger.info("네트워크 인터페이스 자동 감지 중...")

        config = {"nics": {}}
        interfaces = self.get_network_interfaces()

        if not interfaces:
            self.logger.error("활성화된 네트워크 인터페이스를 찾을 수 없습니다")
            sys.exit(1)

        table_id = 100
        metric_base = 100

        for i, interface in enumerate(interfaces.keys()):
            self.logger.info(f"인터페이스 {interface} 정보 수집 중...")

            ip_info = self.get_interface_ip_info(interface)
            if not ip_info:
                self.logger.warning(
                    f"인터페이스 {interface}의 IP 정보를 가져올 수 없습니다"
                )
                continue

            gateway = self.get_default_gateway(interface)
            if not gateway:
                self.logger.warning(
                    f"인터페이스 {interface}의 게이트웨이를 찾을 수 없습니다"
                )
                continue

            nic_name = f"nic{i+1}"
            config["nics"][nic_name] = {
                "interface": interface,
                "ip": ip_info["ip"],
                "network": ip_info["network"],
                "gateway": gateway,
                "metric": metric_base + (i * 100),
                "table_id": table_id + i,
            }

            self.logger.info(
                f"감지된 설정 - {nic_name}: {interface} ({ip_info['ip']}) -> {gateway}"
            )

        if not config["nics"]:
            self.logger.error("유효한 네트워크 인터페이스를 찾을 수 없습니다")
            sys.exit(1)

        self.logger.info(
            f"총 {len(config['nics'])}개의 네트워크 인터페이스가 감지되었습니다"
        )
        return config

    def print_detected_config(self):
        """감지된 설정 출력"""
        print("\n=== 감지된 네트워크 설정 ===")
        for nic_name, nic_config in self.config["nics"].items():
            print(f"{nic_name}:")
            print(f"  인터페이스: {nic_config['interface']}")
            print(f"  IP 주소: {nic_config['ip']}")
            print(f"  네트워크: {nic_config['network']}")
            print(f"  게이트웨이: {nic_config['gateway']}")
            print(f"  메트릭: {nic_config['metric']}")
            print(f"  테이블 ID: {nic_config['table_id']}")
            print()

    def create_udev_rules(self):
        """udev 규칙 생성 - 네트워크 인터페이스 변경 감지"""
        self.logger.info("udev 규칙 생성 중...")

        udev_rule_path = Path("/etc/udev/rules.d/99-pbr-network.rules")

        # udev 규칙 내용
        udev_rule_content = """# Policy Based Routing - Network Interface Detection
# NIC가 추가되거나 IP가 변경될 때 자동으로 PBR 재설정

# 네트워크 인터페이스 UP 이벤트
SUBSYSTEM=="net", ACTION=="add", RUN+="/usr/local/bin/pbr-udev-handler.py add %k"
SUBSYSTEM=="net", ACTION=="change", KERNEL!="lo", RUN+="/usr/local/bin/pbr-udev-handler.py change %k"

# IP 주소 변경 감지를 위한 추가 규칙
SUBSYSTEM=="net", ACTION=="change", ATTR{operstate}=="up", RUN+="/usr/local/bin/pbr-udev-handler.py ip-change %k"
"""

        try:
            udev_rule_path.write_text(udev_rule_content)
            self.logger.info(f"udev 규칙 생성 완료: {udev_rule_path}")

            # udev 규칙 다시 로드
            self.run_command("udevadm control --reload-rules")

        except Exception as e:
            self.logger.error(f"udev 규칙 생성 실패: {e}")

    def create_udev_handler_script(self):
        """udev 이벤트 처리 스크립트 생성"""
        self.logger.info("udev 핸들러 스크립트 생성 중...")

        handler_script_path = Path("/usr/local/bin/pbr-udev-handler.py")

        handler_script_content = f'''#!/usr/bin/env python3
"""
PBR udev 이벤트 핸들러
네트워크 인터페이스 변경 시 Policy Based Routing 자동 재설정
"""

import sys
import subprocess
import time
import logging
from pathlib import Path

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pbr-udev.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def run_command(cmd, ignore_error=False):
    """시스템 명령어 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0 and not ignore_error:
            logger.warning(f"명령어 실행 경고: {{cmd}}")
            logger.warning(f"오류: {{result.stderr}}")
        return result
    except Exception as e:
        logger.error(f"명령어 실행 실패: {{cmd}} - {{e}}")
        return None

def wait_for_ip_assignment(interface, max_wait=30):
    """인터페이스에 IP가 할당될 때까지 대기"""
    logger.info(f"인터페이스 {{interface}}의 IP 할당 대기 중...")
    
    for i in range(max_wait):
        result = run_command(f"ip addr show {{interface}}")
        if result and result.returncode == 0:
            # IPv4 주소가 있는지 확인
            if "inet " in result.stdout and not result.stdout.count("inet ") == result.stdout.count("inet 127."):
                logger.info(f"인터페이스 {{interface}}에 IP가 할당됨")
                return True
        time.sleep(1)
    
    logger.warning(f"인터페이스 {{interface}}의 IP 할당을 {{max_wait}}초간 기다렸지만 할당되지 않음")
    return False

def trigger_pbr_reconfiguration():
    """PBR 재설정 트리거"""
    logger.info("PBR 재설정 트리거 중...")
    
    # 잠시 대기 후 PBR 재설정 실행
    time.sleep(5)  # 시스템이 안정화될 시간을 줌
    
    pbr_script = Path("{os.path.abspath(__file__)}")
    if pbr_script.exists():
        # 기존 설정 제거 후 재설정
        run_command(f"python3 {{pbr_script}} remove", ignore_error=True)
        time.sleep(2)
        result = run_command(f"echo 'y' | python3 {{pbr_script}} setup")
        
        if result and result.returncode == 0:
            logger.info("PBR 재설정 완료")
        else:
            logger.error("PBR 재설정 실패")
    else:
        logger.error(f"PBR 스크립트를 찾을 수 없음: {{pbr_script}}")

def main():
    if len(sys.argv) != 3:
        logger.error("사용법: pbr-udev-handler.py <action> <interface>")
        sys.exit(1)
    
    action = sys.argv[1]
    interface = sys.argv[2]
    
    logger.info(f"udev 이벤트 수신: {{action}} {{interface}}")
    
    # 루프백과 가상 인터페이스 제외
    if (interface == "lo" or 
        interface.startswith("docker") or 
        interface.startswith("veth") or 
        interface.startswith("br-")):
        logger.info(f"인터페이스 {{interface}} 무시됨 (가상 인터페이스)")
        return
    
    if action == "add":
        logger.info(f"새 네트워크 인터페이스 감지: {{interface}}")
        # IP 할당 대기 후 PBR 재설정
        if wait_for_ip_assignment(interface):
            trigger_pbr_reconfiguration()
    
    elif action == "change":
        logger.info(f"네트워크 인터페이스 변경 감지: {{interface}}")
        # 인터페이스 상태 확인 후 필요시 재설정
        result = run_command(f"ip link show {{interface}}")
        if result and "state UP" in result.stdout:
            if wait_for_ip_assignment(interface, max_wait=10):
                trigger_pbr_reconfiguration()
    
    elif action == "ip-change":
        logger.info(f"네트워크 인터페이스 IP 변경 감지: {{interface}}")
        # IP 변경 시 PBR 재설정
        trigger_pbr_reconfiguration()

if __name__ == "__main__":
    main()
'''

        try:
            handler_script_path.write_text(handler_script_content)
            handler_script_path.chmod(0o755)
            self.logger.info(f"udev 핸들러 스크립트 생성 완료: {handler_script_path}")

        except Exception as e:
            self.logger.error(f"udev 핸들러 스크립트 생성 실패: {e}")

    def create_systemd_service(self):
        """systemd 서비스 생성 - 부팅 시 PBR 자동 설정"""
        self.logger.info("systemd 서비스 생성 중...")

        service_path = Path("/etc/systemd/system/pbr-auto-setup.service")

        service_content = f"""[Unit]
Description=Policy Based Routing Auto Setup
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "sleep 10 && echo 'y' | python3 {os.path.abspath(__file__)} setup"
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

        try:
            service_path.write_text(service_content)
            self.logger.info(f"systemd 서비스 생성 완료: {service_path}")

            # 서비스 활성화
            self.run_command("systemctl daemon-reload")
            self.run_command("systemctl enable pbr-auto-setup.service")

        except Exception as e:
            self.logger.error(f"systemd 서비스 생성 실패: {e}")

    def setup_udev_monitoring(self):
        """udev 모니터링 시스템 설정"""
        self.logger.info("udev 모니터링 시스템 설정 중...")

        try:
            # udev 규칙 생성
            self.create_udev_rules()

            # udev 핸들러 스크립트 생성
            self.create_udev_handler_script()

            # systemd 서비스 생성
            self.create_systemd_service()

            # 로그 디렉토리 확인
            log_dir = Path("/var/log")
            if not log_dir.exists():
                log_dir.mkdir(exist_ok=True)

            self.logger.info("udev 모니터링 시스템 설정 완료")
            print("\n=== udev 모니터링 설정 완료 ===")
            print("1. 새로운 NIC가 추가되면 자동으로 PBR 재설정")
            print("2. 기존 NIC의 IP가 변경되면 자동으로 PBR 재설정")
            print("3. 시스템 부팅 시 자동으로 PBR 설정")
            print("4. 로그 파일: /var/log/pbr-udev.log")

        except Exception as e:
            self.logger.error(f"udev 모니터링 시스템 설정 실패: {e}")

    def remove_udev_monitoring(self):
        """udev 모니터링 시스템 제거"""
        self.logger.info("udev 모니터링 시스템 제거 중...")

        try:
            # udev 규칙 제거
            udev_rule_path = Path("/etc/udev/rules.d/99-pbr-network.rules")
            if udev_rule_path.exists():
                udev_rule_path.unlink()
                self.logger.info("udev 규칙 제거됨")

            # udev 핸들러 스크립트 제거
            handler_script_path = Path("/usr/local/bin/pbr-udev-handler.py")
            if handler_script_path.exists():
                handler_script_path.unlink()
                self.logger.info("udev 핸들러 스크립트 제거됨")

            # systemd 서비스 제거
            service_path = Path("/etc/systemd/system/pbr-auto-setup.service")
            if service_path.exists():
                self.run_command(
                    "systemctl disable pbr-auto-setup.service", ignore_error=True
                )
                self.run_command(
                    "systemctl stop pbr-auto-setup.service", ignore_error=True
                )
                service_path.unlink()
                self.run_command("systemctl daemon-reload")
                self.logger.info("systemd 서비스 제거됨")

            # udev 규칙 다시 로드
            self.run_command("udevadm control --reload-rules")

            self.logger.info("udev 모니터링 시스템 제거 완료")

        except Exception as e:
            self.logger.error(f"udev 모니터링 시스템 제거 실패: {e}")

    def check_interface_changes(self):
        """인터페이스 변경 사항 실시간 모니터링 (테스트용)"""
        self.logger.info("네트워크 인터페이스 변경 모니터링 시작...")
        print("네트워크 인터페이스 변경을 모니터링 중입니다...")
        print("Ctrl+C로 중지할 수 있습니다.")

        last_config = self.config.copy()

        try:
            while True:
                time.sleep(5)  # 5초마다 확인

                # 현재 설정 다시 감지
                current_config = self.auto_detect_network_config()

                # 변경 사항 확인
                if current_config != last_config:
                    self.logger.info("네트워크 인터페이스 변경 감지됨!")
                    print("\n=== 네트워크 변경 감지 ===")

                    # 새로 추가된 인터페이스
                    new_nics = set(current_config["nics"].keys()) - set(
                        last_config["nics"].keys()
                    )
                    if new_nics:
                        print(f"새로 추가된 인터페이스: {', '.join(new_nics)}")

                    # 제거된 인터페이스
                    removed_nics = set(last_config["nics"].keys()) - set(
                        current_config["nics"].keys()
                    )
                    if removed_nics:
                        print(f"제거된 인터페이스: {', '.join(removed_nics)}")

                    # 설정 업데이트 및 PBR 재설정
                    self.config = current_config
                    print("PBR 자동 재설정 중...")
                    self.cleanup_existing()
                    self.setup_routing_tables()
                    self.configure_nic_routes()
                    self.setup_policy_rules()
                    self.setup_main_routing()
                    print("PBR 재설정 완료!")

                    last_config = current_config.copy()

        except KeyboardInterrupt:
            print("\n모니터링이 중지되었습니다.")
            self.logger.info("네트워크 인터페이스 모니터링 중지됨")

    def create_backup(self):
        """기존 설정 백업"""
        self.logger.info("기존 설정 백업 중...")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = Path("/tmp/routing_backup")
        backup_dir.mkdir(exist_ok=True)

        # 라우팅 테이블 백업
        if Path("/etc/iproute2/rt_tables").exists():
            self.run_command(
                f"cp /etc/iproute2/rt_tables {backup_dir}/rt_tables_{timestamp}"
            )

        # 현재 라우팅 정보 백업
        self.run_command(f"ip route show > {backup_dir}/routes_{timestamp}.txt")
        self.run_command(f"ip rule show > {backup_dir}/rules_{timestamp}.txt")

        self.logger.info(f"백업 완료: {backup_dir}")

    def cleanup_existing(self):
        """기존 설정 정리"""
        self.logger.info("기존 policy routing 설정 정리 중...")

        for nic_name, nic_config in self.config["nics"].items():
            ip_addr = nic_config["ip"]

            # 기존 policy rules 제거
            self.run_command(
                f"ip rule del from {ip_addr}/32 table {nic_name}", ignore_error=True
            )
            self.run_command(
                f"ip rule del to {ip_addr}/32 table {nic_name}", ignore_error=True
            )

            # 기존 라우팅 테이블 내용 정리
            self.run_command(f"ip route flush table {nic_name}", ignore_error=True)

    def setup_routing_tables(self):
        """라우팅 테이블 설정"""
        self.logger.info("라우팅 테이블 설정 중...")

        rt_tables_path = Path("/etc/iproute2/rt_tables")

        # 기존 내용 읽기
        existing_content = ""
        if rt_tables_path.exists():
            existing_content = rt_tables_path.read_text()

        # 새로운 테이블 추가
        for nic_name, nic_config in self.config["nics"].items():
            table_entry = f"{nic_config['table_id']} {nic_name}"

            if table_entry not in existing_content:
                with open(rt_tables_path, "a") as f:
                    f.write(f"\n{table_entry}\n")
                self.logger.info(f"라우팅 테이블 '{nic_name}' 추가됨")

    def configure_nic_routes(self):
        """각 NIC별 라우팅 테이블 구성"""
        self.logger.info("각 NIC별 라우팅 테이블 구성 중...")

        for nic_name, nic_config in self.config["nics"].items():
            interface = nic_config["interface"]
            gateway = nic_config["gateway"]
            ip_addr = nic_config["ip"]
            network = nic_config["network"]

            self.logger.info(f"NIC {nic_name} ({interface}) 라우팅 설정 중...")

            # 로컬 네트워크 라우트
            self.run_command(
                f"ip route add {network} dev {interface} src {ip_addr} table {nic_name}"
            )

            # 기본 게이트웨이
            self.run_command(
                f"ip route add default via {gateway} dev {interface} table {nic_name}"
            )

    def setup_policy_rules(self):
        """Policy Rules 설정"""
        self.logger.info("Policy Rules 설정 중...")

        for nic_name, nic_config in self.config["nics"].items():
            ip_addr = nic_config["ip"]

            # Source IP 기반 정책
            self.run_command(
                f"ip rule add from {ip_addr}/32 table {nic_name} priority 100"
            )

            # Destination IP 기반 정책
            self.run_command(
                f"ip rule add to {ip_addr}/32 table {nic_name} priority 101"
            )

            self.logger.info(f"NIC {nic_name} (IP: {ip_addr}) Policy Rule 설정 완료")

    def setup_main_routing(self):
        """메인 라우팅 테이블 설정 (metric 기반 우선순위)"""
        self.logger.info("메인 라우팅 테이블 설정 중...")

        # 기존 모든 default 라우트 제거 (더 강력한 방법)
        result = self.run_command("ip route show default")
        if result and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                if line.strip() and "default" in line:
                    self.run_command(f"ip route del {line.strip()}", ignore_error=True)

        # metric 순으로 정렬하여 default 라우트 추가
        sorted_nics = sorted(self.config["nics"].items(), key=lambda x: x[1]["metric"])

        for nic_name, nic_config in sorted_nics:
            interface = nic_config["interface"]
            gateway = nic_config["gateway"]
            metric = nic_config["metric"]

            # 라우트 추가 전에 동일한 라우트가 있는지 확인
            check_result = self.run_command(
                f"ip route show default via {gateway} dev {interface}"
            )
            if not check_result or not check_result.stdout.strip():
                self.run_command(
                    f"ip route add default via {gateway} dev {interface} metric {metric}"
                )
                self.logger.info(
                    f"Default 라우트 추가: {gateway} via {interface} (metric: {metric})"
                )
            else:
                self.logger.info(
                    f"Default 라우트 이미 존재: {gateway} via {interface} (metric: {metric})"
                )

    def check_interfaces(self):
        """네트워크 인터페이스 상태 확인"""
        self.logger.info("네트워크 인터페이스 상태 확인 중...")

        for nic_name, nic_config in self.config["nics"].items():
            interface = nic_config["interface"]

            result = self.run_command(f"ip link show {interface}")
            if result and result.returncode == 0:
                output = result.stdout
                if "state UP" in output:
                    self.logger.info(f"인터페이스 {interface}: UP")
                else:
                    self.logger.warning(f"인터페이스 {interface}: DOWN 또는 상태 불명")
            else:
                self.logger.error(f"인터페이스 {interface}를 찾을 수 없습니다")
                return False
        return True

    def verify_configuration(self):
        """설정 검증"""
        self.logger.info("설정 검증 중...")

        print("\n=== 라우팅 테이블 ===")
        result = self.run_command(
            "cat /etc/iproute2/rt_tables | grep -E '^[0-9]+.*nic[0-9]+'"
        )
        if result:
            print(result.stdout)

        print("\n=== Policy Rules ===")
        result = self.run_command("ip rule show")
        if result:
            print(result.stdout)

        print("\n=== 메인 라우팅 테이블의 Default 라우트 ===")
        result = self.run_command("ip route show | grep default")
        if result:
            print(result.stdout)

        for nic_name in self.config["nics"].keys():
            print(f"\n=== NIC {nic_name} 라우팅 테이블 ===")
            result = self.run_command(f"ip route show table {nic_name}")
            if result:
                print(result.stdout)

    def create_startup_script(self):
        """시스템 시작시 자동 적용을 위한 스크립트 생성"""
        self.logger.info("시작시 자동 적용 스크립트 생성 중...")

        startup_script = Path("/etc/network/if-up.d/policy-routing-python")

        script_content = f"""#!/usr/bin/env python3
import subprocess
import json

config = {json.dumps(self.config, indent=2)}

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=False)
    except:
        pass

# Policy rules 재설정
for nic_name, nic_config in config['nics'].items():
    ip_addr = nic_config['ip']
    run_cmd(f"ip rule add from {{ip_addr}}/32 table {{nic_name}} priority 100")
    run_cmd(f"ip rule add to {{ip_addr}}/32 table {{nic_name}} priority 101")
"""

        startup_script.write_text(script_content)
        startup_script.chmod(0o755)

        self.logger.info(f"시작시 자동 적용 스크립트 생성 완료: {startup_script}")

    def run_connectivity_test(self):
        """연결성 테스트"""
        self.logger.info("연결성 테스트 실행 중...")

        for nic_name, nic_config in self.config["nics"].items():
            interface = nic_config["interface"]
            ip_addr = nic_config["ip"]
            gateway = nic_config["gateway"]

            print(f"\n=== NIC {nic_name} ({interface}) 테스트 ===")

            # 게이트웨이 ping 테스트
            result = self.run_command(f"ping -c 1 -W 2 -I {ip_addr} {gateway}")
            if result and result.returncode == 0:
                self.logger.info(f"게이트웨이 {gateway} 연결 성공")
            else:
                self.logger.warning(f"게이트웨이 {gateway} 연결 실패")

            # 외부 DNS 테스트
            result = self.run_command(f"ping -c 1 -W 2 -I {ip_addr} 8.8.8.8")
            if result and result.returncode == 0:
                self.logger.info("외부 연결 (8.8.8.8) 성공")
            else:
                self.logger.warning("외부 연결 실패")

    def setup(self):
        """전체 설정 실행"""
        print("=" * 50)
        print("  Ubuntu 22.04 Multi-NIC Policy Based Routing")
        print("  Python Implementation with Auto-Detection")
        print("=" * 50)

        # 감지된 설정 출력
        self.print_detected_config()

        # 사용자 확인
        response = input("위 설정으로 진행하시겠습니까? (y/N): ")
        if response.lower() != "y":
            print("설정이 취소되었습니다.")
            return False

        try:
            self.create_backup()

            if not self.check_interfaces():
                self.logger.error("인터페이스 확인 실패")
                return False

            self.cleanup_existing()
            self.setup_routing_tables()
            self.configure_nic_routes()
            self.setup_policy_rules()
            self.setup_main_routing()
            self.verify_configuration()
            self.create_startup_script()

            # udev 모니터링 시스템 설정 추가
            self.setup_udev_monitoring()

            self.run_connectivity_test()

            print("\n" + "=" * 50)
            print("  Policy Based Routing 설정이 완료되었습니다!")
            print("=" * 50)
            print("주요 설정:")
            print("1. 외부에서 들어온 패킷은 동일한 NIC로 응답")
            print("2. 내부 → 외부 패킷은 metric 우선순위에 따라 라우팅")
            print("3. 시스템 재시작시 자동 적용됨")
            print("4. 새로운 NIC 추가/변경시 자동 재설정")

            return True

        except Exception as e:
            self.logger.error(f"설정 중 오류 발생: {e}")
            return False

    def remove_configuration(self):
        """설정 제거"""
        self.logger.info("Policy routing 설정 제거 중...")

        # Policy rules 제거
        for nic_name, nic_config in self.config["nics"].items():
            ip_addr = nic_config["ip"]
            self.run_command(
                f"ip rule del from {ip_addr}/32 table {nic_name}", ignore_error=True
            )
            self.run_command(
                f"ip rule del to {ip_addr}/32 table {nic_name}", ignore_error=True
            )
            self.run_command(f"ip route flush table {nic_name}", ignore_error=True)

        # 시작 스크립트 제거
        startup_script = Path("/etc/network/if-up.d/policy-routing-python")
        if startup_script.exists():
            startup_script.unlink()

        # udev 모니터링 시스템 제거
        self.remove_udev_monitoring()

        self.logger.info("설정 제거 완료")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Ubuntu 22.04 Policy Based Routing Manager"
    )
    parser.add_argument(
        "action",
        choices=["setup", "remove", "verify", "detect", "monitor"],
        help="수행할 작업",
    )

    args = parser.parse_args()

    manager = PolicyBasedRoutingManager()

    if args.action == "setup":
        manager.setup()
    elif args.action == "remove":
        manager.remove_configuration()
    elif args.action == "verify":
        manager.verify_configuration()
    elif args.action == "detect":
        manager.print_detected_config()
    elif args.action == "monitor":
        manager.check_interface_changes()


if __name__ == "__main__":
    main()
