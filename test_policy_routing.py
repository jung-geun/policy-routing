import sys
import os
# 현재 스크립트의 디렉토리를 sys.path에 추가하여 policy_routing 모듈을 찾을 수 있도록 함
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

import unittest
from unittest.mock import patch, MagicMock
import unittest.mock as mock
import json
import subprocess
import logging
import ipaddress

# policy-routing.py에서 필요한 클래스와 상수 임포트
import policy_routing

# 로깅 비활성화 (테스트 시 불필요한 로그 출력 방지)
logging.disable(logging.CRITICAL)

class TestPolicyRoutingManager(unittest.TestCase):

    def setUp(self):
        """각 테스트 전에 실행될 초기화 코드"""
        # 테스트용 임시 설정 파일 경로 설정
        self.test_config_file = "/tmp/test_policy_routing.json"
        self.test_rt_tables_file = "/tmp/test_rt_tables"
        
        # CONFIG_FILE과 RT_TABLES_FILE을 테스트용으로 오버라이드
        # 실제 파일에 영향을 주지 않도록 패치
        self.config_file_patch = patch('policy_routing.CONFIG_FILE', self.test_config_file)
        self.rt_tables_file_patch = patch('policy_routing.RT_TABLES_FILE', self.test_rt_tables_file)
        
        self.mock_config_file = self.config_file_patch.start()
        self.mock_rt_tables_file = self.rt_tables_file_patch.start()

        # 임시 설정 파일 생성 (기본값으로)
        with open(self.test_config_file, 'w') as f:
            json.dump(policy_routing.DEFAULT_CONFIG, f, indent=2)
        
        # 임시 rt_tables 파일 생성
        with open(self.test_rt_tables_file, 'w') as f:
            f.write("#\n# reserved values\n#\n255\tlocal\n254\tmain\n253\tdefault\n0\tunspec\n")

        self.manager = policy_routing.PolicyRoutingManager(debug=True)
        # 로거를 테스트용으로 변경하여 실제 파일에 쓰지 않도록 함
        self.manager.logger = MagicMock()

    def tearDown(self):
        """각 테스트 후에 실행될 정리 코드"""
        # 임시 파일 삭제
        if os.path.exists(self.test_config_file):
            os.remove(self.test_config_file)
        if os.path.exists(self.test_rt_tables_file):
            os.remove(self.test_rt_tables_file)
        
        self.config_file_patch.stop()
        self.rt_tables_file_patch.stop()

    def test_calculate_network(self):
        """calculate_network 함수 테스트"""
        self.assertEqual(self.manager.calculate_network("192.168.1.100", "24"), "192.168.1.0/24")
        self.assertEqual(self.manager.calculate_network("10.0.0.5", "8"), "10.0.0.0/8")
        self.assertEqual(self.manager.calculate_network("172.16.10.20", "16"), "172.16.0.0/16")
        self.assertEqual(self.manager.calculate_network("192.168.1.1", "30"), "192.168.1.0/30")
        
        # 잘못된 IP 형식
        self.assertEqual(self.manager.calculate_network("invalid-ip", "24"), "0.0.0.0/24")
        # 잘못된 넷마스크
        self.assertEqual(self.manager.calculate_network("192.168.1.100", "abc"), "0.0.0.0/abc") # 이 경우 폴백 로직에 따라 달라질 수 있음
        self.assertEqual(self.manager.calculate_network("192.168.1.100", "33"), "0.0.0.0/33") # 유효하지 않은 넷마스크

    @patch('subprocess.run')
    def test_run_command_success(self, mock_run):
        """run_command 성공 케이스 테스트"""
        mock_run.return_value = MagicMock(stdout="Success output", stderr="", returncode=0)
        success, output = self.manager.run_command(["echo", "hello"])
        self.assertTrue(success)
        self.assertEqual(output, "Success output")
        mock_run.assert_called_once_with(["echo", "hello"], capture_output=True, text=True, check=True)
        self.manager.logger.debug.assert_any_call("실행: echo hello")
        self.manager.logger.debug.assert_any_call("성공: echo hello")
        self.manager.logger.debug.assert_any_call("출력: Success output")

    @patch('subprocess.run')
    def test_run_command_failure(self, mock_run):
        """run_command 실패 케이스 테스트"""
        mock_run.side_effect = subprocess.CalledProcessError(returncode=1, cmd=["bad", "cmd"], stderr="Error output")
        success, output = self.manager.run_command(["bad", "cmd"])
        self.assertFalse(success)
        self.assertEqual(output, "Error output")
        self.manager.logger.error.assert_called_once_with("명령어 실행 실패: bad cmd - Error output")

    @patch('subprocess.run')
    def test_run_command_ignore_errors(self, mock_run):
        """run_command 특정 오류 무시 케이스 테스트"""
        mock_run.side_effect = subprocess.CalledProcessError(returncode=1, cmd=["ip", "route", "flush"], stderr="No such file or directory")
        success, output = self.manager.run_command(["ip", "route", "flush"], ignore_errors=["No such file or directory"])
        self.assertTrue(success)
        self.assertEqual(output, "")
        
        self.manager.logger.error.assert_not_called()
        self.manager.logger.debug.assert_any_call("무시된 오류: ip route flush - No such file or directory")
        self.manager.logger.debug.assert_any_call("실행: ip route flush")
        self.assertEqual(self.manager.logger.debug.call_count, 2)

    @patch('policy_routing.PolicyRoutingManager.run_command')
    def test_get_network_interfaces(self, mock_run_command):
        """get_network_interfaces 함수 테스트"""
        # 시뮬레이션할 ip addr show 출력
        mock_run_command.side_effect = [
            (True, """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:12:34:56 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.10/24 brd 192.168.1.255 scope global dynamic eth0
       valid_lft 86399sec preferred_lft 86399sec
    inet6 fe80::20c:29ff:fe12:3456/64 scope link
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:ab:cd:ef brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.5/8 brd 10.255.255.255 scope global dynamic eth1
       valid_lft 86399sec preferred_lft 86399sec
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:1c:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
            """),
            # _find_gateway를 위한 mock (eth0)
            (True, "default via 192.168.1.1 dev eth0"),
            # _find_gateway를 위한 mock (eth1)
            (True, "default via 10.0.0.1 dev eth1")
        ]

        interfaces = self.manager.get_network_interfaces()
        self.assertEqual(len(interfaces), 2)

        eth0 = next(filter(lambda x: x['name'] == 'eth0', interfaces))
        self.assertEqual(eth0['ip'], '192.168.1.10')
        self.assertEqual(eth0['netmask'], '24')
        self.assertEqual(eth0['gateway'], '192.168.1.1')
        self.assertEqual(eth0['state'], 'UP')

        eth1 = next(filter(lambda x: x['name'] == 'eth1', interfaces))
        self.assertEqual(eth1['ip'], '10.0.0.5')
        self.assertEqual(eth1['netmask'], '8')
        self.assertEqual(eth1['gateway'], '10.0.0.1')
        self.assertEqual(eth1['state'], 'UP')
        
        # docker0와 lo는 제외되어야 함
        self.assertNotIn('docker0', [i['name'] for i in interfaces])
        self.assertNotIn('lo', [i['name'] for i in interfaces])

    def test__find_gateway(self):
        """_find_gateway 함수 테스트"""
        # Case 1: Gateway found in interface-specific route
        with patch('policy_routing.PolicyRoutingManager.run_command') as mock_run_command:
            mock_run_command.side_effect = [
                (True, "default via 192.168.1.1 dev eth0 proto static")
            ]
            self.assertEqual(self.manager._find_gateway("eth0"), "192.168.1.1")
            mock_run_command.assert_called_once_with(["ip", "route", "show", "dev", "eth0"])

        # Case 2: Gateway found in global route after interface-specific fails
        with patch('policy_routing.PolicyRoutingManager.run_command') as mock_run_command:
            mock_run_command.side_effect = [
                (True, "192.168.1.0/24 dev eth1 proto kernel"), # No default via
                (True, "default via 10.0.0.1 dev eth1 proto static") # Found in global
            ]
            self.assertEqual(self.manager._find_gateway("eth1"), "10.0.0.1")
            self.assertEqual(mock_run_command.call_count, 2)
            mock_run_command.assert_has_calls([
                mock.call(["ip", "route", "show", "dev", "eth1"]),
                mock.call(["ip", "route", "show"])
            ])

        # Case 3: No gateway found (empty output for both)
        with patch('policy_routing.PolicyRoutingManager.run_command') as mock_run_command:
            mock_run_command.side_effect = [
                (True, ""), # No default via
                (True, "")  # No default via in global
            ]
            self.assertIsNone(self.manager._find_gateway("eth2"))
            self.assertEqual(mock_run_command.call_count, 2)

        # Case 4: No gateway found (error for both)
        with patch('policy_routing.PolicyRoutingManager.run_command') as mock_run_command:
            mock_run_command.side_effect = [
                (False, "Error dev"),
                (False, "Error global")
            ]
            self.assertIsNone(self.manager._find_gateway("eth3"))
            self.assertEqual(mock_run_command.call_count, 2)

    @patch('policy_routing.PolicyRoutingManager.run_command')
    def test_apply_interface_routing(self, mock_run_command):
        """apply_interface_routing 함수 테스트"""
        interface_info = {
            "name": "eth0",
            "ip": "192.168.1.10",
            "gateway": "192.168.1.1",
            "netmask": "24",
            "state": "UP"
        }
        table_id = 101
        priority = 30100

        # run_command의 side_effect를 설정하여 각 호출에 대한 응답을 시뮬레이션
        # 순서대로 호출될 명령에 대한 응답을 정의
        mock_run_command.side_effect = [
            (True, ""), # 1. ip rule del from 192.168.1.10/32
            (True, ""), # 2. ip route show table 101 (empty, so flush is skipped)
            (True, ""), # 3. ip route add network
            (True, ""), # 4. ip route add default
            (True, ""), # 5. ip rule add from
            (True, ""), # 6. ip rule add iif
            (True, "30100: from 192.168.1.10 lookup 101"), # 7. ip rule show (verification)
            (True, "default via 192.168.1.1 dev eth0 table 101") # 8. ip route show table 101 (verification)
        ]

        success = self.manager.apply_interface_routing(interface_info, table_id, priority)
        
        self.assertTrue(success)
        self.manager.logger.error.assert_not_called()

        # run_command 호출 검증
        expected_calls = [
            mock.call(['ip', 'route', 'show', 'table', '101']), # This is the first call
            mock.call(['ip', 'rule', 'del', 'from', '192.168.1.10/32'], ignore_errors=['No such file or directory']), # This is the second call
            # mock.call(['ip', 'route', 'flush', 'table', '101'], ignore_errors=['No such file or directory']), # Removed, as table is empty
            mock.call(['ip', 'route', 'add', '192.168.1.0/24', 'dev', 'eth0', 'src', '192.168.1.10', 'table', '101'], ignore_errors=['File exists']),
            mock.call(['ip', 'route', 'add', 'default', 'via', '192.168.1.1', 'dev', 'eth0', 'table', '101'], ignore_errors=['File exists']),
            mock.call(['ip', 'rule', 'add', 'from', '192.168.1.10/32', 'table', '101', 'pref', '30100'], ignore_errors=['File exists']),
            mock.call(['ip', 'rule', 'add', 'iif', 'eth0', 'table', '101', 'pref', '30101'], ignore_errors=['File exists']),
            mock.call(['ip', 'rule', 'show']),
            mock.call(['ip', 'route', 'show', 'table', '101'])
        ]
        mock_run_command.assert_has_calls(expected_calls)
        self.assertEqual(mock_run_command.call_count, len(expected_calls))


if __name__ == '__main__':
    unittest.main()
