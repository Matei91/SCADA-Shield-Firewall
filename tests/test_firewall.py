"""
=============================================================================
TESTE UNITARE: tests/test_firewall.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Suita cuprinzatoare de teste unitare automate pentru verificarea tuturor
    mecanismelor de protectie, decodarii protocolului Modbus TCP, politicilor
    DPI, limitatorului de rata si modelului de inteligenta artificiala.
=============================================================================
"""

import os
import sys
import unittest
import time

# Adaugam radacina proiectului in path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from firewall.modbus_packet import ModbusPacket
from firewall.rate_limiter import TokenBucketRateLimiter
from firewall.rule_engine import ICSFirewallRuleEngine
from firewall.ai_inspector import AITrafficInspector
from firewall.core_firewall import ICSCoreFirewall
from simulation.virtual_plc import VirtualPLC
from simulation.attack_simulator import SCADAAttackSimulator


class TestICSFirewall(unittest.TestCase):
    """
    Test suite pentru validarea firewall-ului industrial SCADA-Shield.
    """

    def setUp(self):
        """
        Configurare instanta inainte de fiecare test.
        """
        self.firewall = ICSCoreFirewall()
        self.plc = VirtualPLC()
        self.attacker = SCADAAttackSimulator()

    def test_01_modbus_packet_encoding_and_decoding(self):
        """
        Testeaza serializarea binara si parsarea unui cadru Modbus TCP (MBAP + PDU).
        """
        original = ModbusPacket(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.50",
            src_port=51234,
            dst_port=502,
            transaction_id=42,
            protocol_id=0,
            length=6,
            unit_id=1,
            function_code=3,
            register_address=1000,
            register_value=4.0
        )

        raw_bytes = original.to_bytes()
        self.assertGreaterEqual(len(raw_bytes), 12, "Lungimea cadrului binar Modbus TCP trebuie sa fie minim 12 octeti.")

        decoded = ModbusPacket.from_bytes(
            raw_bytes,
            src_ip=original.src_ip,
            dst_ip=original.dst_ip,
            src_port=original.src_port,
            dst_port=original.dst_port
        )

        self.assertEqual(decoded.transaction_id, 42)
        self.assertEqual(decoded.protocol_id, 0)
        self.assertEqual(decoded.unit_id, 1)
        self.assertEqual(decoded.function_code, 3)
        self.assertEqual(decoded.register_address, 1000)
        self.assertEqual(decoded.register_value, 4.0)
        self.assertTrue(decoded.is_read_operation)
        self.assertFalse(decoded.is_write_operation)

    def test_02_read_only_enforcement_rule(self):
        """
        Valideaza regula R003: Cand modul Read-Only este activ, toate comenzile
        de scriere sunt blocate, iar cele de citire sunt permise.
        """
        self.firewall.read_only_mode = True

        # 1. Pachet de citire (FC 03) de la HMI legitim -> Trebuie permis
        read_packet = ModbusPacket(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.50",
            function_code=3,
            register_address=1000,
            register_value=1.0
        )
        res_read = self.firewall.process_packet(read_packet)
        self.assertEqual(res_read.decision, "ALLOW", "Citirea trebuie sa fie permisa in regim Read-Only!")

        # 2. Pachet de scriere (FC 06) de la statia de inginerie -> Trebuie blocat in regim Read-Only
        write_packet = ModbusPacket(
            src_ip="192.168.1.20",
            dst_ip="192.168.1.50",
            function_code=6,
            register_address=1010,
            register_value=50.0
        )
        res_write = self.firewall.process_packet(write_packet)
        self.assertEqual(res_write.decision, "DROP", "Scrierea trebuie sa fie respinsa in regim Read-Only!")
        self.assertEqual(res_write.triggered_rule, "R003_READ_ONLY_ENFORCEMENT")

    def test_03_ip_whitelisting(self):
        """
        Valideaza regula R002: Pachetele de la adrese IP neautorizate (ex: 192.168.1.99)
        trebuie sa fie respinse imediat.
        """
        unauthorized_packet = ModbusPacket(
            src_ip="192.168.1.99",  # IP atacator
            dst_ip="192.168.1.50",
            function_code=3,
            register_address=1000,
            register_value=1.0
        )
        res = self.firewall.process_packet(unauthorized_packet)
        self.assertEqual(res.decision, "DROP")
        self.assertEqual(res.triggered_rule, "R002_IP_WHITELIST")

    def test_04_physical_safety_limits_inspection(self):
        """
        Valideaza regula R006: Cand modul read_only este dezactivat, statia de inginerie
        poate scrie valori, dar orice valoare care depaseste limitele sigure de proces
        (ex: presiune 500 PSI) este blocata de Semantic DPI.
        """
        self.firewall.read_only_mode = False

        # Valoare periculoasa: 500 PSI (limita maxima sigura este 80 PSI)
        danger_packet = ModbusPacket(
            src_ip="192.168.1.20",  # Statia de inginerie autorizata
            dst_ip="192.168.1.50",
            function_code=6,
            register_address=1010,  # Pressure_Setpoint
            register_value=500.0    # Pericol explozie!
        )
        res = self.firewall.process_packet(danger_packet)
        self.assertEqual(res.decision, "DROP")
        self.assertEqual(res.triggered_rule, "R006_PHYSICAL_LIMITS_VIOLATION")

    def test_05_critical_register_protection(self):
        """
        Valideaza protectia registrelor critice de siguranta (Coils 2000-2010 - Valva Oprire Urgenta).
        """
        self.firewall.read_only_mode = False

        valve_packet = ModbusPacket(
            src_ip="192.168.1.20",
            dst_ip="192.168.1.50",
            function_code=5,
            register_address=2001,  # Emergency_Shutoff_Valve
            register_value=1.0
        )
        res = self.firewall.process_packet(valve_packet)
        self.assertEqual(res.decision, "DROP")
        self.assertEqual(res.triggered_rule, "R005_CRITICAL_REGISTER_PROTECTION")

    def test_06_rate_limiter_dos_prevention(self):
        """
        Valideaza modulul de Rate Limiter impotriva atacurilor de tip DoS / Flood pe portul 502.
        """
        limiter = TokenBucketRateLimiter(rate=50.0, burst=20)
        ip = "192.168.1.99"
        now = time.time()

        # Primele 20 de pachete (burst) trec
        allowed_count = 0
        for _ in range(20):
            if limiter.check_and_consume(ip, timestamp=now):
                allowed_count += 1
        self.assertEqual(allowed_count, 20)

        # Urmatoarele pachete in aceeasi secunda trebuie sa fie respinse
        blocked_count = 0
        for _ in range(50):
            if not limiter.check_and_consume(ip, timestamp=now):
                blocked_count += 1
        self.assertGreater(blocked_count, 0, "Rate Limiter-ul trebuie sa respinga pachetele peste burst!")

    def test_07_virtual_plc_physics_simulation(self):
        """
        Valideaza comportamentul fizic al PLC-ului virtual.
        """
        self.plc.reset_state()
        initial_state = self.plc.get_state()
        self.assertFalse(initial_state["is_pipeline_ruptured"])
        self.assertEqual(initial_state["pressure_setpoint"], 50.0)

        # Simulam comanda legitima de reglare presiune la 60 PSI
        cmd = ModbusPacket(function_code=6, register_address=1010, register_value=60.0)
        self.plc.execute_packet(cmd)
        for _ in range(5):
            self.plc.step_physics(dt=0.5)

        updated_state = self.plc.get_state()
        self.assertGreater(updated_state["pressure_psi"], 50.0, "Presiunea fizica trebuie sa creasca catre noul setpoint.")
        self.assertFalse(updated_state["is_pipeline_ruptured"])

    def test_08_attack_scenarios_prevention(self):
        """
        Testeaza ca toate scenariile majore de atac sunt respinse de firewall.
        """
        # Scenariul 1: Unauthorized write
        p1 = self.attacker.scenario_unauthorized_write()[0]
        res1 = self.firewall.process_packet(p1)
        self.assertEqual(res1.decision, "DROP")

        # Scenariul 2: Critical setpoint tampering
        p2 = self.attacker.scenario_critical_setpoint_tampering()[0]
        res2 = self.firewall.process_packet(p2)
        self.assertEqual(res2.decision, "DROP")

        # Scenariul 5: Evasion via Protocol ID corruption
        p5 = self.attacker.scenario_protocol_evasion()[0]
        res5 = self.firewall.process_packet(p5)
        self.assertEqual(res5.decision, "DROP")


if __name__ == "__main__":
    unittest.main()
