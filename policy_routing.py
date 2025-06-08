#!/usr/bin/env python3
"""
Ubuntu 22.04 Multi-NIC Policy Based Routing Setup Script
Python Implementation
"""

__version__ = "0.3"  # 현재 스크립트 버전

import subprocess
import logging
import os
import sys
import json
import re
import ipaddress
from datetime import datetime
from pathlib import Path
import requests  # requests 라이브러리 추가


class PolicyBasedRoutingManager:
    def __init__(self):
        # 로깅 설정
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger(__name__)
        self.config_file_path = Path("/etc/pbr_nics.json")

        # 권한 확인
        if os.geteuid() != 0:
            self.logger.error("이 스크립트는 root 권한으로 실행해야 합니다.")
            sys.exit(1)

        # 네트워크 인터페이스 설정 (초기에는 비워둠)
        self.config = {"nics": {}}
        self.github_repo_url = "https://raw.githubusercontent.com/jung-geun/policy-routing/main/policy_routing.py"

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

    def get_latest_version(self):
        """GitHub에서 최신 버전 정보 가져오기"""
        try:
            response = requests.get(self.github_repo_url)
            response.raise_for_status()  # HTTP 오류 발생 시 예외 발생

            # 파일 내용에서 __version__ 라인 찾기
            for line in response.text.splitlines():
                if "__version__" in line:
                    match = re.search(
                        r'__version__\s*=\s*["\'](\d+\.\d+\.\d+)["\']', line
                    )
                    if match:
                        return match.group(1)
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"최신 버전 정보를 가져오는 데 실패했습니다: {e}")
            return None

    def check_for_updates(self):
        """업데이트 확인 및 사용자에게 알림"""
        self.logger.info("최신 버전 확인 중...")
        latest_version = self.get_latest_version()
        current_version = __version__

        if latest_version:
            self.logger.info(
                f"현재 버전: {current_version}, 최신 버전: {latest_version}"
            )

            # 버전 비교 (간단한 문자열 비교, 실제로는 semantic versioning 라이브러리 사용 권장)
            if latest_version > current_version:
                self.logger.info("새로운 버전이 사용 가능합니다!")
                response = input("업데이트를 진행하시겠습니까? (y/N): ")
                if response.lower() == "y":
                    return True
                else:
                    self.logger.info("업데이트가 취소되었습니다.")
                    return False
            else:
                self.logger.info("현재 최신 버전을 사용 중입니다.")
                return False
        else:
            self.logger.warning(
                "최신 버전 정보를 가져올 수 없어 업데이트 확인을 건너뜁니다."
            )
            return False

    def perform_update(self):
        """스크립트를 최신 버전으로 업데이트"""
        self.logger.info("스크립트 업데이트를 시작합니다...")
        try:
            response = requests.get(self.github_repo_url)
            response.raise_for_status()  # HTTP 오류 발생 시 예외 발생

            script_content = response.text
            current_script_path = Path(sys.argv[0])  # 현재 실행 중인 스크립트의 경로

            # 현재 스크립트 파일을 백업
            backup_path = current_script_path.with_suffix(
                f".py.bak_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
            current_script_path.rename(backup_path)
            self.logger.info(f"현재 스크립트 백업 완료: {backup_path}")

            # 최신 내용으로 스크립트 파일 덮어쓰기
            with open(current_script_path, "w") as f:
                f.write(script_content)

            # 실행 권한 유지
            current_script_path.chmod(0o755)

            self.logger.info(
                "스크립트 업데이트가 성공적으로 완료되었습니다. 스크립트를 다시 실행해주세요."
            )
            sys.exit(0)  # 업데이트 후 스크립트 재시작을 위해 종료
        except requests.exceptions.RequestException as e:
            self.logger.error(f"스크립트 다운로드 실패: {e}")
        except Exception as e:
            self.logger.error(f"스크립트 업데이트 중 오류 발생: {e}")
        return False

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
                    and not interface.startswith("ovs-")
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
            return config  # Return empty config instead of sys.exit(1)

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
            return config  # Return empty config instead of sys.exit(1)

        self.logger.info(
            f"총 {len(config['nics'])}개의 네트워크 인터페이스가 감지되었습니다"
        )
        return config

    def _save_nic_config(self, config_data):
        """현재 NIC 설정을 파일에 저장"""
        try:
            with open(self.config_file_path, "w") as f:
                json.dump(config_data, f, indent=2)
            self.logger.info(f"NIC 설정 저장 완료: {self.config_file_path}")
        except Exception as e:
            self.logger.error(f"NIC 설정 저장 실패: {e}")

    def _load_nic_config(self):
        """이전에 저장된 NIC 설정을 파일에서 로드"""
        if self.config_file_path.exists():
            try:
                with open(self.config_file_path, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                self.logger.error(f"NIC 설정 파일 읽기 오류 (JSON): {e}")
            except Exception as e:
                self.logger.error(f"NIC 설정 파일 로드 실패: {e}")
        return {"nics": {}}

    def detect_nic_changes(self):
        """NIC 변경 사항 (추가/제거) 감지"""
        current_nics = self.auto_detect_network_config()["nics"]
        previous_config = self._load_nic_config()
        previous_nics = previous_config.get("nics", {})

        added_nics = {}
        removed_nics = {}

        # 추가된 NIC 감지
        for nic_name, nic_config in current_nics.items():
            if nic_name not in previous_nics:
                added_nics[nic_name] = nic_config
                self.logger.info(
                    f"새로운 NIC 감지됨: {nic_name} ({nic_config['interface']})"
                )

        # 제거된 NIC 감지
        for nic_name, nic_config in previous_nics.items():
            if nic_name not in current_nics:
                removed_nics[nic_name] = nic_config
                self.logger.info(
                    f"NIC 제거 감지됨: {nic_name} ({nic_config['interface']})"
                )

        # 기존 NIC 중 변경된 정보가 있는지 확인 (IP, Gateway 등)
        # 이 부분은 현재 스크립트의 auto_detect_network_config가 nicX 이름을 순서대로 부여하므로
        # 인터페이스 이름으로 비교하는 것이 더 정확할 수 있습니다.
        # 여기서는 단순화하여 nic_name 기준으로만 추가/제거를 판단합니다.
        # 더 정교한 변경 감지가 필요하면 interface 이름으로 매핑하여 비교 로직을 추가해야 합니다.

        return added_nics, removed_nics, current_nics

    def _add_single_nic_config(self, nic_name, nic_config):
        """단일 NIC에 대한 라우팅 테이블, 라우트, 정책 규칙 추가"""
        self.logger.info(f"NIC {nic_name} ({nic_config['interface']}) 설정 추가 중...")

        # 1. 라우팅 테이블 설정
        rt_tables_path = Path("/etc/iproute2/rt_tables")
        table_entry = f"{nic_config['table_id']} {nic_name}"

        existing_content = ""
        if rt_tables_path.exists():
            existing_content = rt_tables_path.read_text()

        if table_entry not in existing_content:
            with open(rt_tables_path, "a") as f:
                f.write(f"\n{table_entry}\n")
            self.logger.info(f"라우팅 테이블 '{nic_name}' 추가됨")

        # 2. NIC별 라우팅 테이블 구성
        interface = nic_config["interface"]
        gateway = nic_config["gateway"]
        ip_addr = nic_config["ip"]
        network = nic_config["network"]

        self.run_command(
            f"ip route add {network} dev {interface} src {ip_addr} table {nic_name}"
        )
        self.run_command(
            f"ip route add default via {gateway} dev {interface} table {nic_name}"
        )

        # 3. Policy Rules 설정
        self.run_command(f"ip rule add from {ip_addr}/32 table {nic_name} priority 100")
        self.run_command(f"ip rule add to {ip_addr}/32 table {nic_name} priority 101")
        self.logger.info(f"NIC {nic_name} 설정 추가 완료")

    def _remove_single_nic_config(self, nic_name, nic_config):
        """단일 NIC에 대한 라우팅 테이블, 라우트, 정책 규칙 제거"""
        self.logger.info(f"NIC {nic_name} ({nic_config['interface']}) 설정 제거 중...")

        ip_addr = nic_config["ip"]
        table_id = nic_config["table_id"]

        # 1. Policy rules 제거
        self.run_command(
            f"ip rule del from {ip_addr}/32 table {nic_name}", ignore_error=True
        )
        self.run_command(
            f"ip rule del to {ip_addr}/32 table {nic_name}", ignore_error=True
        )

        # 2. 라우팅 테이블 내용 정리
        self.run_command(f"ip route flush table {nic_name}", ignore_error=True)

        # 3. /etc/iproute2/rt_tables 에서 항목 제거
        rt_tables_path = Path("/etc/iproute2/rt_tables")
        if rt_tables_path.exists():
            try:
                lines = rt_tables_path.read_text().splitlines()
                new_lines = [
                    line
                    for line in lines
                    if not (
                        line.strip().startswith(str(table_id))
                        and nic_name in line.strip()
                    )
                ]
                rt_tables_path.write_text("\n".join(new_lines) + "\n")
                self.logger.info(f"라우팅 테이블 '{nic_name}' 항목 제거됨")
            except Exception as e:
                self.logger.warning(f"rt_tables 파일 수정 중 오류 발생: {e}")

        self.logger.info(f"NIC {nic_name} 설정 제거 완료")

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

    def setup_main_routing(self):
        """메인 라우팅 테이블 설정 (metric 기반 우선순위)"""
        self.logger.info("메인 라우팅 테이블 설정 중...")

        # 기존 default 라우트 제거
        self.run_command("ip route del default", ignore_error=True)

        # DNS 서버 목록 (널리 사용되는 공용 DNS)
        dns_servers = [
            "8.8.8.8",      # Google DNS
            "8.8.4.4",      # Google DNS
            "1.1.1.1",      # Cloudflare DNS
            "1.0.0.1",      # Cloudflare DNS
            "208.67.222.222",  # OpenDNS
            "208.67.220.220",  # OpenDNS
        ]

        # 기존 DNS 서버 라우트 제거
        for dns in dns_servers:
            self.run_command(f"ip route del {dns}", ignore_error=True)

        # metric 순으로 정렬하여 default 라우트 추가
        sorted_nics = sorted(self.config["nics"].items(), key=lambda x: x[1]["metric"])

        for nic_name, nic_config in sorted_nics:
            interface = nic_config["interface"]
            gateway = nic_config["gateway"]
            metric = nic_config["metric"]

            self.run_command(
                f"ip route add default via {gateway} dev {interface} metric {metric}"
            )
            self.logger.info(
                f"Default 라우트 추가: {gateway} via {interface} (metric: {metric})"
            )

        # DNS 서버들을 NIC별로 분산하여 라우팅 설정
        self.logger.info("DNS 서버 라우팅 설정 중...")
        
        for i, dns in enumerate(dns_servers):
            # DNS 서버를 NIC 개수만큼 순환하여 분산
            nic_index = i % len(sorted_nics)
            nic_name, nic_config = sorted_nics[nic_index]
            
            interface = nic_config["interface"]
            gateway = nic_config["gateway"]
            metric = nic_config["metric"]
            
            self.run_command(
                f"ip route add {dns} via {gateway} dev {interface} metric {metric}"
            )
            self.logger.info(
                f"DNS 라우트 추가: {dns} via {gateway} (interface: {interface}, metric: {metric})"
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

    def apply_dynamic_rules(self):
        """NIC 변경 사항을 감지하고 동적으로 규칙을 적용/제거"""
        self.logger.info("동적 NIC 규칙 적용 중...")
        added_nics, removed_nics, current_nics = self.detect_nic_changes()

        # 제거된 NIC 설정 정리
        for nic_name, nic_config in removed_nics.items():
            self._remove_single_nic_config(nic_name, nic_config)

        # 추가된 NIC 설정 적용
        for nic_name, nic_config in added_nics.items():
            self._add_single_nic_config(nic_name, nic_config)

        # 현재 활성 NIC 목록으로 self.config 업데이트 및 저장
        self.config["nics"] = current_nics
        self._save_nic_config(self.config)

        # 메인 라우팅 테이블은 전체 NIC 기반으로 재설정
        self.setup_main_routing()
        self.logger.info("동적 NIC 규칙 적용 완료.")

    def create_startup_script(self):
        """시스템 시작시 자동 적용을 위한 스크립트 생성"""
        self.logger.info("시작시 자동 적용 스크립트 생성 중...")

        startup_script = Path("/etc/network/if-up.d/policy-routing-python")

        script_content = f"""#!/usr/bin/env python3
import subprocess
import json
import sys
import os
import re
import ipaddress
from pathlib import Path
import logging

# 로깅 설정 (스크립트 실행 시 로그를 남기기 위함)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class StartupPolicyBasedRoutingManager:
    def __init__(self):
        self.logger = logger
        self.config_file_path = Path("/etc/pbr_nics.json")

    def run_command(self, cmd, ignore_error=False):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0 and not ignore_error:
                self.logger.warning(f"명령어 실행 경고: {{cmd}}")
                self.logger.warning(f"오류: {{result.stderr}}")
            return result
        except Exception as e:
            self.logger.error(f"명령어 실행 실패: {{cmd}} - {{e}}")
            return None

    def get_network_interfaces(self):
        interfaces = {{}}
        result = self.run_command("ip link show")
        if not result or result.returncode != 0:
            self.logger.error("네트워크 인터페이스를 가져올 수 없습니다")
            return interfaces
        for line in result.stdout.split("\\n"):
            match = re.match(r"^\\d+:\\s+(\\w+):", line)
            if match:
                interface = match.group(1)
                if (
                    interface != "lo"
                    and not interface.startswith("docker")
                    and not interface.startswith("veth")
                    and not interface.startswith("br-")
                    and "state UP" in line
                ):
                    interfaces[interface] = {{}}
        return interfaces

    def get_interface_ip_info(self, interface):
        result = self.run_command(f"ip addr show {{interface}}")
        if not result or result.returncode != 0:
            return None
        ip_info = {{}}
        for line in result.stdout.split("\\n"):
            match = re.search(r"inet (\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+)", line)
            if match:
                ip_addr = match.group(1)
                prefix = int(match.group(2))
                network = ipaddress.IPv4Network(f"{{ip_addr}}/{{prefix}}", strict=False)
                ip_info = {{
                    "ip": ip_addr,
                    "prefix": prefix,
                    "network": str(network),
                    "netmask": str(network.netmask),
                }}
                break
        return ip_info

    def get_default_gateway(self, interface):
        result = self.run_command(f"ip route show dev {{interface}}")
        if not result or result.returncode != 0:
            return None
        for line in result.stdout.split("\\n"):
            if "default via" in line:
                match = re.search(r"default via (\\d+\\.\\d+\\.\\d+\\.\\d+)", line)
                if match:
                    return match.group(1)
        ip_info = self.get_interface_ip_info(interface)
        if ip_info:
            network = ipaddress.IPv4Network(ip_info["network"])
            gateway = str(network.network_address + 1)
            return gateway
        return None

    def auto_detect_network_config(self):
        config = {{"nics": {{}}}}
        interfaces = self.get_network_interfaces()
        if not interfaces:
            self.logger.error("활성화된 네트워크 인터페이스를 찾을 수 없습니다")
            return config # Return empty config instead of sys.exit(1) for startup script
        table_id = 100
        metric_base = 100
        for i, interface in enumerate(interfaces.keys()):
            ip_info = self.get_interface_ip_info(interface)
            if not ip_info:
                self.logger.warning(f"인터페이스 {{interface}}의 IP 정보를 가져올 수 없습니다")
                continue
            gateway = self.get_default_gateway(interface)
            if not gateway:
                self.logger.warning(f"인터페이스 {{interface}}의 게이트웨이를 찾을 수 없습니다")
                continue
            nic_name = f"nic{{i+1}}"
            config["nics"][nic_name] = {{
                "interface": interface,
                "ip": ip_info["ip"],
                "network": ip_info["network"],
                "gateway": gateway,
                "metric": metric_base + (i * 100),
                "table_id": table_id + i,
            }}
        return config

    def _save_nic_config(self, config_data):
        try:
            with open(self.config_file_path, "w") as f:
                json.dump(config_data, f, indent=2)
            self.logger.info(f"NIC 설정 저장 완료: {{self.config_file_path}}")
        except Exception as e:
            self.logger.error(f"NIC 설정 저장 실패: {{e}}")

    def _load_nic_config(self):
        if self.config_file_path.exists():
            try:
                with open(self.config_file_path, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                self.logger.error(f"NIC 설정 파일 읽기 오류 (JSON): {{e}}")
            except Exception as e:
                self.logger.error(f"NIC 설정 파일 로드 실패: {{e}}")
        return {{"nics": {{}}}}

    def detect_nic_changes(self):
        current_nics = self.auto_detect_network_config()["nics"]
        previous_config = self._load_nic_config()
        previous_nics = previous_config.get("nics", {{}})

        added_nics = {{}}
        removed_nics = {{}}

        for nic_name, nic_config in current_nics.items():
            if nic_name not in previous_nics:
                added_nics[nic_name] = nic_config
                self.logger.info(f"새로운 NIC 감지됨: {{nic_name}} ({{nic_config['interface']}})")

        for nic_name, nic_config in previous_nics.items():
            if nic_name not in current_nics:
                removed_nics[nic_name] = nic_config
                self.logger.info(f"NIC 제거 감지됨: {{nic_name}} ({{nic_config['interface']}})")
        
        return added_nics, removed_nics, current_nics

    def _add_single_nic_config(self, nic_name, nic_config):
        self.logger.info(f"NIC {{nic_name}} ({{nic_config['interface']}}) 설정 추가 중...")
        rt_tables_path = Path("/etc/iproute2/rt_tables")
        table_entry = f"{{nic_config['table_id']}} {{nic_name}}"

        existing_content = ""
        if rt_tables_path.exists():
            existing_content = rt_tables_path.read_text()

        if table_entry not in existing_content:
            with open(rt_tables_path, "a") as f:
                f.write(f"\\n{{table_entry}}\\n")
            self.logger.info(f"라우팅 테이블 '{{nic_name}}' 추가됨")

        interface = nic_config["interface"]
        gateway = nic_config["gateway"]
        ip_addr = nic_config["ip"]
        network = nic_config["network"]

        self.run_command(f"ip route add {{network}} dev {{interface}} src {{ip_addr}} table {{nic_name}}")
        self.run_command(f"ip route add default via {{gateway}} dev {{interface}} table {{nic_name}}")
        self.run_command(f"ip rule add from {{ip_addr}}/32 table {{nic_name}} priority 100")
        self.run_command(f"ip rule add to {{ip_addr}}/32 table {{nic_name}} priority 101")
        self.logger.info(f"NIC {{nic_name}} 설정 추가 완료")

    def _remove_single_nic_config(self, nic_name, nic_config):
        self.logger.info(f"NIC {{nic_name}} ({{nic_config['interface']}}) 설정 제거 중...")
        ip_addr = nic_config["ip"]
        table_id = nic_config["table_id"]

        self.run_command(f"ip rule del from {{ip_addr}}/32 table {{nic_name}}", ignore_error=True)
        self.run_command(f"ip rule del to {{ip_addr}}/32 table {{nic_name}}", ignore_error=True)
        self.run_command(f"ip route flush table {{nic_name}}", ignore_error=True)

        rt_tables_path = Path("/etc/iproute2/rt_tables")
        if rt_tables_path.exists():
            try:
                lines = rt_tables_path.read_text().splitlines()
                new_lines = [
                    line
                    for line in lines
                    if not (
                        line.strip().startswith(str(table_id))
                        and nic_name in line.strip()
                    )
                ]
                rt_tables_path.write_text("\\n".join(new_lines) + "\\n")
                self.logger.info(f"라우팅 테이블 '{{nic_name}}' 항목 제거됨")
            except Exception as e:
                self.logger.warning(f"rt_tables 파일 수정 중 오류 발생: {{e}}")
        self.logger.info(f"NIC {{nic_name}} 설정 제거 완료")

    def setup_main_routing(self, current_nics):
        self.logger.info("메인 라우팅 테이블 설정 중...")
        self.run_command("ip route del default", ignore_error=True)
        
        # DNS 서버 목록 (널리 사용되는 공용 DNS)
        dns_servers = [
            "8.8.8.8",      # Google DNS
            "8.8.4.4",      # Google DNS
            "1.1.1.1",      # Cloudflare DNS
            "1.0.0.1",      # Cloudflare DNS
            "208.67.222.222",  # OpenDNS
            "208.67.220.220",  # OpenDNS
        ]

        # 기존 DNS 서버 라우트 제거
        for dns in dns_servers:
            self.run_command(f"ip route del {{dns}}", ignore_error=True)
        
        sorted_nics = sorted(current_nics.items(), key=lambda x: x[1]["metric"])
        for nic_name, nic_config in sorted_nics:
            interface = nic_config["interface"]
            gateway = nic_config["gateway"]
            metric = nic_config["metric"]
            self.run_command(f"ip route add default via {{gateway}} dev {{interface}} metric {{metric}}")
            self.logger.info(f"Default 라우트 추가: {{gateway}} via {{interface}} (metric: {{metric}})")
        
        # DNS 서버들을 NIC별로 분산하여 라우팅 설정
        self.logger.info("DNS 서버 라우팅 설정 중...")
        
        for i, dns in enumerate(dns_servers):
            # DNS 서버를 NIC 개수만큼 순환하여 분산
            nic_index = i % len(sorted_nics)
            nic_name, nic_config = sorted_nics[nic_index]
            
            interface = nic_config["interface"]
            gateway = nic_config["gateway"]
            metric = nic_config["metric"]
            
            self.run_command(f"ip route add {{dns}} via {{gateway}} dev {{interface}} metric {{metric}}")
            self.logger.info(f"DNS 라우트 추가: {{dns}} via {{gateway}} (interface: {{interface}}, metric: {{metric}})")

def main_startup():
    manager = StartupPolicyBasedRoutingManager()
    
    added_nics, removed_nics, current_nics = manager.detect_nic_changes()

    for nic_name, nic_config in removed_nics.items():
        manager._remove_single_nic_config(nic_name, nic_config)

    for nic_name, nic_config in added_nics.items():
        manager._add_single_nic_config(nic_name, nic_config)

    manager._save_nic_config({{"nics": current_nics}})
    manager.setup_main_routing(current_nics)

if __name__ == "__main__":
    main_startup()
"""

        startup_script.write_text(script_content)
        startup_script.chmod(0o755)

        self.logger.info(f"시작시 자동 적용 스크립트 생성 완료: {startup_script}")

    def create_shutdown_script(self):
        """시스템 종료시 자동 적용을 위한 스크립트 생성"""
        self.logger.info("종료시 자동 적용 스크립트 생성 중...")

        shutdown_script = Path("/etc/network/if-down.d/policy-routing-python-down")

        os.makedirs(shutdown_script.parent, exist_ok=True)

        script_content = f"""#!/usr/bin/env python3
import subprocess
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def run_command(cmd, ignore_error=False):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0 and not ignore_error:
            logger.warning(f"명령어 실행 경고: {{cmd}}")
            logger.warning(f"오류: {{result.stderr}}")
        return result
    except Exception as e:
        logger.error(f"명령어 실행 실패: {{cmd}} - {{e}}")
        return None

def main_shutdown():
    logger.info("정책 기반 라우팅 종료 스크립트 실행 중...")
    # pbr.py remove를 호출하여 모든 라우팅 규칙 및 테이블을 정리합니다.
    run_command("/usr/bin/python3 /home/pieroot/pbr/pbr.py remove")
    logger.info("정책 기반 라우팅 종료 스크립트 실행 완료.")

if __name__ == "__main__":
    main_shutdown()
"""
        shutdown_script.write_text(script_content)
        shutdown_script.chmod(0o755)

        self.logger.info(f"종료시 자동 적용 스크립트 생성 완료: {shutdown_script}")

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

    def setup(self, force=False):
        """전체 설정 실행"""
        print("=" * 50)
        print("  Ubuntu 22.04 Multi-NIC Policy Based Routing")
        print("  Python Implementation with Auto-Detection")
        print("=" * 50)

        # 네트워크 인터페이스 자동 감지 및 설정 업데이트
        self.config = self.auto_detect_network_config()

        # 감지된 설정 출력
        self.print_detected_config()

        # 사용자 확인 (force 모드일 경우 건너뛰기)
        if not force:
            response = input("위 설정으로 진행하시겠습니까? (y/N): ")
            if response.lower() != "y":
                print("설정이 취소되었습니다.")
                return False

        try:
            self.create_backup()

            if not self.check_interfaces():
                self.logger.error("인터페이스 확인 실패")
                return False

            added_nics, removed_nics, current_nics = self.detect_nic_changes()

            # 제거된 NIC 설정 정리
            for nic_name, nic_config in removed_nics.items():
                self._remove_single_nic_config(nic_name, nic_config)

            # 추가된 NIC 설정 적용
            for nic_name, nic_config in added_nics.items():
                self._add_single_nic_config(nic_name, nic_config)

            # 현재 활성 NIC 목록으로 self.config 업데이트
            self.config["nics"] = current_nics
            self._save_nic_config(self.config)  # 변경된 설정 저장

            self.setup_main_routing()  # 메인 라우팅 테이블은 전체 NIC 기반으로 재설정
            self.verify_configuration()
            self.create_startup_script()
            self.create_shutdown_script()
            self.run_connectivity_test()

            print("\n" + "=" * 50)
            print("  Policy Based Routing 설정이 완료되었습니다!")
            print("=" * 50)
            print("주요 설정:")
            print("1. 외부에서 들어온 패킷은 동일한 NIC로 응답")
            print("2. 내부 → 외부 패킷은 metric 우선순위에 따라 라우팅")
            print("3. 시스템 재시작시 자동 적용됨")

            return True

        except Exception as e:
            self.logger.error(f"설정 중 오류 발생: {e}")
            return False

    def remove_configuration(self):
        """설정 제거"""
        self.logger.info("Policy routing 설정 제거 중...")

        # 현재 감지된 NIC와 저장된 NIC를 모두 고려하여 제거
        current_nics = self.auto_detect_network_config()["nics"]
        previous_config = self._load_nic_config()
        all_nics_to_remove = {**current_nics, **previous_config.get("nics", {})}

        for nic_name, nic_config in all_nics_to_remove.items():
            self._remove_single_nic_config(nic_name, nic_config)

        # 시작 스크립트 제거
        startup_script = Path("/etc/network/if-up.d/policy-routing-python")
        if startup_script.exists():
            startup_script.unlink()
            self.logger.info(f"시작 스크립트 제거 완료: {startup_script}")

        # 종료 스크립트 제거
        shutdown_script = Path("/etc/network/if-down.d/policy-routing-python-down")
        if shutdown_script.exists():
            shutdown_script.unlink()
            self.logger.info(f"종료 스크립트 제거 완료: {shutdown_script}")

        # 저장된 NIC 설정 파일 제거
        if self.config_file_path.exists():
            try:
                self.config_file_path.unlink()
                self.logger.info(
                    f"저장된 NIC 설정 파일 제거 완료: {self.config_file_path}"
                )
            except Exception as e:
                self.logger.warning(f"저장된 NIC 설정 파일 제거 실패: {e}")

        self.logger.info("설정 제거 완료")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Ubuntu 22.04 Policy Based Routing Manager"
    )
    parser.add_argument(
        "action",
        choices=["setup", "remove", "verify", "detect", "apply_changes"],
        help="수행할 작업",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="설정 시 사용자 확인 프롬프트를 건너뜁니다.",
    )

    args = parser.parse_args()

    manager = PolicyBasedRoutingManager()

    # 스크립트 시작 시 업데이트 확인
    if manager.check_for_updates():
        manager.perform_update()
        # perform_update는 성공 시 sys.exit(0)을 호출하므로, 이 아래 코드는 실행되지 않음

    if args.action == "setup":
        manager.setup(force=args.force)
    elif args.action == "remove":
        manager.remove_configuration()
    elif args.action == "verify":
        manager.verify_configuration()
    elif args.action == "detect":
        manager.print_detected_config()
    elif args.action == "apply_changes":
        manager.apply_dynamic_rules()


if __name__ == "__main__":
    main()
