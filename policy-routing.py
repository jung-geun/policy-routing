#!/usr/bin/env python3
"""
Policy-Based Routing Manager - 실시간 네트워크 변화 감지 개선 버전
"""

import os
import sys
import json
import time
import subprocess
import argparse
import logging
import signal
import threading
import socket
import struct
import select
from pathlib import Path
from typing import Dict, List, Optional, Set

# 설정 상수
CONFIG_FILE = "/etc/policy_routing.json"
SERVICE_FILE = "/etc/systemd/system/policy-routing.service"
UDEV_RULE_FILE = "/etc/udev/rules.d/99-policy-routing.rules"
SCRIPT_PATH = "/usr/local/bin/policy_routing.py"
RT_TABLES_FILE = "/etc/iproute2/rt_tables"

# Netlink 상수
NETLINK_ROUTE = 0
RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_NEWADDR = 20
RTM_DELADDR = 21

# 기본 설정
DEFAULT_CONFIG = {
    "enabled": True,
    "log_level": "INFO",
    "check_interval": 5,  # 더 빠른 체크
    "interfaces": {},
    "global_settings": {
        "base_table_id": 100,
        "base_priority": 30000
    },
    "monitoring": {
        "use_netlink": True,
        "use_udev": True,
        "use_polling": True
    }
}

class NetlinkMonitor:
    """Netlink 소켓을 통한 실시간 네트워크 변화 감지"""
    
    def __init__(self, callback):
        self.callback = callback
        self.running = False
        self.sock = None
        self.logger = logging.getLogger('netlink')
        
    def start(self):
        """Netlink 모니터링 시작"""
        try:
            self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
            self.sock.bind((os.getpid(), 0))
            
            # 관심 있는 그룹에 가입
            groups = (1 << (25-1)) | (1 << (26-1))  # RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            self.sock.setsockopt(socket.SOL_NETLINK, socket.NETLINK_ADD_MEMBERSHIP, 1)  # RTNLGRP_LINK
            self.sock.setsockopt(socket.SOL_NETLINK, socket.NETLINK_ADD_MEMBERSHIP, 5)  # RTNLGRP_IPV4_IFADDR
            
            self.running = True
            self.logger.info("Netlink 모니터링 시작됨")
            
            while self.running:
                ready, _, _ = select.select([self.sock], [], [], 1.0)
                if ready:
                    data = self.sock.recv(4096)
                    self._parse_netlink_message(data)
                    
        except Exception as e:
            self.logger.error(f"Netlink 모니터링 오류: {e}")
        finally:
            if self.sock:
                self.sock.close()
                
    def stop(self):
        """Netlink 모니터링 중지"""
        self.running = False
        
    def _parse_netlink_message(self, data):
        """Netlink 메시지 파싱"""
        try:
            if len(data) < 16:
                return
                
            # Netlink 헤더 파싱
            nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack("IHHII", data[:16])
            
            if nlmsg_type in [RTM_NEWLINK, RTM_DELLINK, RTM_NEWADDR, RTM_DELADDR]:
                action = "add" if nlmsg_type in [RTM_NEWLINK, RTM_NEWADDR] else "remove"
                self.logger.info(f"Netlink 이벤트 감지: {action} (type: {nlmsg_type})")
                self.callback("netlink", action)
                
        except Exception as e:
            self.logger.error(f"Netlink 메시지 파싱 오류: {e}")

class PolicyRoutingManager:
    def __init__(self):
        self.config = {}
        self.running = False
        self.interfaces_state = {}
        self.managed_tables = set()
        self.logger = self._setup_logging()
        self.netlink_monitor = None
        self.last_interface_check = {}
        
    def _setup_logging(self):
        """로깅 설정"""
        logger = logging.getLogger('policy_routing')
        logger.setLevel(logging.INFO)
        
        # 콘솔 핸들러
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # 포맷터
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger

    def network_change_callback(self, source: str, action: str):
        """네트워크 변화 콜백"""
        self.logger.info(f"네트워크 변화 감지됨 (source: {source}, action: {action})")
        # 즉시 인터페이스 체크 수행
        threading.Thread(target=self._immediate_interface_check, daemon=True).start()
        
    def _immediate_interface_check(self):
        """즉시 인터페이스 체크"""
        try:
            time.sleep(1)  # 짧은 딜레이로 설정이 안정화되길 기다림
            self._check_and_apply_interfaces()
        except Exception as e:
            self.logger.error(f"즉시 인터페이스 체크 오류: {e}")

    def load_config(self) -> Dict:
        """설정 파일 로드"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # 기본값과 병합
                    for key, value in DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                    return config
            else:
                return DEFAULT_CONFIG.copy()
        except Exception as e:
            self.logger.error(f"설정 파일 로드 실패: {e}")
            return DEFAULT_CONFIG.copy()

    def save_config(self, config: Dict):
        """설정 파일 저장"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            self.logger.info(f"설정 파일 저장됨: {CONFIG_FILE}")
        except Exception as e:
            self.logger.error(f"설정 파일 저장 실패: {e}")

    def run_command(self, cmd: List[str], ignore_errors: List[str] = None) -> bool:
        """명령어 실행 (오류 처리 개선)"""
        if ignore_errors is None:
            ignore_errors = []
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            
            # 특정 오류는 무시
            for ignore_pattern in ignore_errors:
                if ignore_pattern in error_msg:
                    return True
                    
            self.logger.error(f"명령어 실행 실패 {' '.join(cmd)}: {error_msg}")
            return False

    def get_network_interfaces(self) -> List[Dict]:
        """네트워크 인터페이스 정보 수집"""
        interfaces = []
        try:
            # ip addr show 명령어로 인터페이스 정보 수집
            result = subprocess.run(['ip', 'addr', 'show'], 
                                  capture_output=True, text=True, check=True)
            
            current_iface = None
            for line in result.stdout.split('\n'):
                if line and not line.startswith(' '):
                    # 새 인터페이스 시작
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface_name = parts[1].strip()
                        if iface_name not in ['lo', 'docker0'] and not iface_name.startswith(('veth', 'br-', 'virbr')):
                            current_iface = {
                                'name': iface_name,
                                'ip': None,
                                'gateway': None,
                                'state': 'DOWN'
                            }
                            # 상태 확인
                            if 'UP' in line and 'LOWER_UP' in line:
                                current_iface['state'] = 'UP'
                elif current_iface and 'inet ' in line and 'scope global' in line:
                    # IP 주소 추출
                    parts = line.strip().split()
                    for i, part in enumerate(parts):
                        if part == 'inet' and i + 1 < len(parts):
                            current_iface['ip'] = parts[i + 1].split('/')[0]
                            current_iface['netmask'] = parts[i + 1].split('/')[1] if '/' in parts[i + 1] else '24'
                            break
                    
                    if current_iface['ip'] and current_iface not in interfaces:
                        # 게이트웨이 찾기
                        try:
                            gw_result = subprocess.run(
                                ['ip', 'route', 'show', 'dev', current_iface['name']], 
                                capture_output=True, text=True
                            )
                            for gw_line in gw_result.stdout.split('\n'):
                                if 'default via' in gw_line:
                                    current_iface['gateway'] = gw_line.split('via')[1].split()[0]
                                    break
                                    
                        except Exception:
                            pass
                        
                        if current_iface['gateway']:
                            interfaces.append(current_iface)
                        current_iface = None
                        
        except Exception as e:
            self.logger.error(f"인터페이스 정보 수집 실패: {e}")
            
        return interfaces

    def setup_routing_table(self, interface_name: str, table_id: int):
        """라우팅 테이블 설정"""
        try:
            with open(RT_TABLES_FILE, 'r') as f:
                content = f.read()
            
            table_line = f"{table_id}\t{interface_name}\n"
            if table_line not in content:
                with open(RT_TABLES_FILE, 'a') as f:
                    f.write(table_line)
                self.logger.info(f"라우팅 테이블 {table_id} ({interface_name}) 추가됨")
                
        except Exception as e:
            self.logger.error(f"라우팅 테이블 설정 실패: {e}")

    def apply_interface_routing(self, interface_info: Dict, table_id: int, priority: int) -> bool:
        """인터페이스별 라우팅 규칙 적용"""
        name = interface_info['name']
        ip = interface_info['ip']
        gateway = interface_info['gateway']
        netmask = interface_info.get('netmask', '24')
        
        if not all([name, ip, gateway]):
            return False

        # 상태 변화가 있는지 확인
        current_state = f"{ip}:{gateway}:{table_id}"
        if self.last_interface_check.get(name) == current_state:
            return True
            
        try:
            network = f"{'.'.join(ip.split('.')[:-1])}.0/{netmask}"
            
            # 기존 규칙 정리
            subprocess.run(['ip', 'rule', 'del', 'from', f"{ip}/32"], capture_output=True)
            subprocess.run(['ip', 'route', 'del', 'default', 'table', str(table_id)], capture_output=True)
            
            # 새 규칙 추가
            commands = [
                ['ip', 'route', 'add', network, 'dev', name, 'src', ip, 'table', str(table_id)],
                ['ip', 'route', 'add', 'default', 'via', gateway, 'dev', name, 'table', str(table_id)],
                ['ip', 'rule', 'add', 'from', f"{ip}/32", 'table', str(table_id), 'pref', str(priority)]
            ]
            
            for cmd in commands:
                if not self.run_command(cmd, ignore_errors=['File exists', 'No such file or directory']):
                    return False
            
            self.last_interface_check[name] = current_state
            self.managed_tables.add(table_id)
            self.logger.info(f"인터페이스 {name} 라우팅 설정 완료 (table: {table_id})")
            return True
            
        except Exception as e:
            self.logger.error(f"인터페이스 {name} 라우팅 설정 실패: {e}")
            return False

    def _check_and_apply_interfaces(self):
        """인터페이스 체크 및 적용"""
        try:
            interfaces = self.get_network_interfaces()
            current_interfaces = {iface['name']: iface for iface in interfaces}
            
            config_changed = False
            
            for name, info in current_interfaces.items():
                if info['state'] == 'UP' and info['ip'] and info['gateway']:
                    if name not in self.config['interfaces']:
                        table_id = self.config['global_settings']['base_table_id'] + len(self.config['interfaces'])
                        self.config['interfaces'][name] = {
                            'enabled': True,
                            'table_id': table_id,
                            'priority': 100,
                            'health_check_target': '8.8.8.8'
                        }
                        config_changed = True
                        self.logger.info(f"새 인터페이스 {name} 자동 추가됨")
                    
                    if self.config['interfaces'][name]['enabled']:
                        iface_config = self.config['interfaces'][name]
                        table_id = iface_config['table_id']
                        priority = self.config['global_settings']['base_priority'] + iface_config['priority']
                        
                        self.setup_routing_table(name, table_id)
                        self.apply_interface_routing(info, table_id, priority)
            
            if config_changed:
                self.save_config(self.config)
                
        except Exception as e:
            self.logger.error(f"인터페이스 체크 오류: {e}")

    def monitor_interfaces(self):
        """인터페이스 모니터링 (폴링 방식)"""
        while self.running:
            try:
                self._check_and_apply_interfaces()
                time.sleep(self.config['check_interval'])
            except Exception as e:
                self.logger.error(f"모니터링 오류: {e}")
                time.sleep(5)

    def start_daemon(self):
        """데몬 모드 시작"""
        self.config = self.load_config()
        self.running = True
        
        # 신호 핸들러 등록
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGHUP, self._reload_config)
        
        self.logger.info("Policy Routing Manager 시작됨")
        
        # Netlink 모니터링 시작 (설정에 따라)
        if self.config.get('monitoring', {}).get('use_netlink', True):
            self.netlink_monitor = NetlinkMonitor(self.network_change_callback)
            netlink_thread = threading.Thread(target=self.netlink_monitor.start, daemon=True)
            netlink_thread.start()
        
        # 폴링 모니터링 시작
        if self.config.get('monitoring', {}).get('use_polling', True):
            monitor_thread = threading.Thread(target=self.monitor_interfaces, daemon=True)
            monitor_thread.start()
        
        # 초기 설정 적용
        self._check_and_apply_interfaces()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop_daemon()

    def stop_daemon(self):
        """데몬 중지"""
        self.running = False
        if self.netlink_monitor:
            self.netlink_monitor.stop()
        self.logger.info("Policy Routing Manager 중지됨")

    def _signal_handler(self, signum, frame):
        """신호 처리"""
        self.logger.info(f"신호 {signum} 수신됨")
        if signum == signal.SIGHUP:
            self._reload_config(signum, frame)
        else:
            self.stop_daemon()

    def _reload_config(self, signum, frame):
        """설정 재로드"""
        self.logger.info("설정 재로드 중...")
        self.config = self.load_config()
        self._check_and_apply_interfaces()

    def refresh_from_external(self):
        """외부(udev 등)에서 호출되는 새로고침"""
        self.logger.info("외부 트리거로 새로고침 요청됨")
        self.network_change_callback("external", "refresh")

# [PolicyRoutingInstaller 클래스는 이전과 동일]
class PolicyRoutingInstaller:
    def __init__(self):
        self.logger = logging.getLogger('installer')
        
    def check_requirements(self) -> bool:
        if os.geteuid() != 0:
            print("오류: 관리자 권한이 필요합니다.")
            return False
            
        required_commands = ['ip', 'systemctl']
        for cmd in required_commands:
            try:
                subprocess.run(['which', cmd], check=True, capture_output=True)
            except subprocess.CalledProcessError:
                print(f"오류: {cmd} 명령어를 찾을 수 없습니다.")
                return False
        return True

    def install(self):
        if not self.check_requirements():
            return False
            
        try:
            script_content = open(__file__, 'r').read()
            with open(SCRIPT_PATH, 'w') as f:
                f.write(script_content)
            os.chmod(SCRIPT_PATH, 0o755)
            
            service_content = f"""[Unit]
Description=Policy-Based Routing Manager
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart={SCRIPT_PATH} daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
            with open(SERVICE_FILE, 'w') as f:
                f.write(service_content)
            
            # 개선된 udev 규칙
            udev_content = f"""# Policy Routing udev rules
SUBSYSTEM=="net", ACTION=="add", RUN+="{SCRIPT_PATH} refresh"
SUBSYSTEM=="net", ACTION=="remove", RUN+="{SCRIPT_PATH} refresh"
SUBSYSTEM=="net", ACTION=="change", RUN+="{SCRIPT_PATH} refresh"
SUBSYSTEM=="net", ACTION=="move", RUN+="{SCRIPT_PATH} refresh"
"""
            with open(UDEV_RULE_FILE, 'w') as f:
                f.write(udev_content)
            
            # udev 규칙 재로드
            subprocess.run(['udevadm', 'control', '--reload-rules'], check=True)
            subprocess.run(['udevadm', 'trigger', '--subsystem-match=net'], check=True)
            
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'enable', 'policy-routing'], check=True)
            
            if not os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'w') as f:
                    json.dump(DEFAULT_CONFIG, f, indent=2)
            
            print("✅ Policy Routing Manager 설치 완료!")
            print("   - Netlink 실시간 모니터링 지원")
            print("   - 개선된 udev 규칙")
            print("   - 폴링 백업 모니터링")
            
            return True
            
        except Exception as e:
            print(f"❌ 설치 실패: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Policy-Based Routing Manager')
    parser.add_argument('action', choices=[
        'install', 'uninstall', 'daemon', 'status', 'refresh', 'config', 'clean', 'test-udev'
    ], help='실행할 작업')
    
    args = parser.parse_args()
    
    if args.action == 'install':
        installer = PolicyRoutingInstaller()
        installer.install()
        
    elif args.action == 'daemon':
        manager = PolicyRoutingManager()
        manager.start_daemon()
        
    elif args.action == 'refresh':
        manager = PolicyRoutingManager()
        manager.refresh_from_external()
        
    elif args.action == 'test-udev':
        # udev 규칙 테스트
        print("🔍 udev 이벤트 모니터링 중... (Ctrl+C로 중지)")
        print("새 네트워크 인터페이스를 연결해보세요.")
        os.system("udevadm monitor --environment --udev --subsystem-match=net")
        
    elif args.action == 'status':
        manager = PolicyRoutingManager()
        interfaces = manager.get_network_interfaces()
        print("📡 네트워크 인터페이스 상태:")
        for iface in interfaces:
            print(f"  - {iface['name']}: {iface['ip']} -> {iface['gateway']} ({iface['state']})")
        
        # udev 규칙 상태 확인
        if os.path.exists(UDEV_RULE_FILE):
            print(f"\n✅ udev 규칙 설치됨: {UDEV_RULE_FILE}")
        else:
            print(f"\n❌ udev 규칙 없음: {UDEV_RULE_FILE}")

if __name__ == '__main__':
    main()