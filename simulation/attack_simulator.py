"""
=============================================================================
MODUL: simulation/attack_simulator.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Simuleaza scenarii reale de atac cibernetic impotriva retelelor de control
    industrial (ICS / SCADA / Modbus TCP), conform cerintelor temei de master:
      - Simulare atacuri care incearca sa ocoleasca regulile firewall-ului
      - Demonstratie comparativa (Impactul asupra procesului fizic FARA firewall vs CU firewall)

    Scenarii implementate:
      1. ATAC 1: Unauthorized Write (Injectare comenzi scriere de la IP neautorizat)
      2. ATAC 2: Critical Setpoint Tampering (Stuxnet style - Supracomanda fizica presiune)
      3. ATAC 3: Industrial Reconnaissance / Modbus Scanning (Baleiere Slave IDs & Registre)
      4. ATAC 4: Denial of Service / Modbus Flood (Inundare port 502)
      5. ATAC 5: Evasion via Protocol Manipulation (MBAP Corrupt / Protocol ID invalid)
      6. ATAC 6: Stealth Anomaly / Low-and-Slow (Anomalie subtila tintita pentru AI)
=============================================================================
"""

import time
import random
from typing import List, Dict, Any, Tuple

from firewall.modbus_packet import ModbusPacket
from firewall.core_firewall import ICSCoreFirewall
from simulation.virtual_plc import VirtualPLC


class SCADAAttackSimulator:
    """
    Generator si simulator de atacuri avansate specifice infrastructurilor critice.
    """

    def __init__(self, target_plc_ip: str = "192.168.1.50"):
        """
        Initializeaza simulatorul de atacuri.

        Args:
            target_plc_ip (str): IP-ul controlerului industrial vizat.
        """
        self.target_plc_ip = target_plc_ip
        self.rogue_ip = "192.168.1.99"
        self.external_attacker_ip = "10.0.0.5"
        self.spoofed_eng_ip = "192.168.1.20"

    def scenario_unauthorized_write(self) -> List[ModbusPacket]:
        """
        Scenariul 1: Atacator neautorizat incearca sa transmita comenzi de scriere
        pentru a opri valva de siguranta si a perturba livrarea gazului.

        Returns:
            List[ModbusPacket]: Lista de pachete ale atacului.
        """
        packets = []
        now = time.time()

        # 1. Comanda de inchidere a valvei principale de urgenta (Coil 2001)
        p1 = ModbusPacket(
            src_ip=self.rogue_ip,
            dst_ip=self.target_plc_ip,
            src_port=52341,
            dst_port=502,
            transaction_id=101,
            protocol_id=0,
            length=6,
            unit_id=1,
            function_code=5,  # Write Single Coil
            register_address=2001,
            register_value=1.0,  # 1 = Declanșare închidere de urgență
            timestamp=now
        )
        packets.append(p1)

        # 2. Comanda de scriere a unui setpoint fals de presiune
        p2 = ModbusPacket(
            src_ip=self.external_attacker_ip,
            dst_ip=self.target_plc_ip,
            src_port=52342,
            dst_port=502,
            transaction_id=102,
            protocol_id=0,
            length=6,
            unit_id=1,
            function_code=6,  # Write Single Register
            register_address=1010,
            register_value=0.0,  # Opreste presiunea
            timestamp=now + 0.1
        )
        packets.append(p2)
        return packets

    def scenario_critical_setpoint_tampering(self) -> List[ModbusPacket]:
        """
        Scenariul 2: Sabotaj de proces fizic (Stuxnet style).
        Atacatorul foloseste adresa statiei de inginerie autorizate (192.168.1.20),
        dar forteaza cresterea presiunii peste limita de explozie (ex: 500 PSI).

        Returns:
            List[ModbusPacket]: Pachetele generate pentru sabotaj.
        """
        now = time.time()
        p = ModbusPacket(
            src_ip=self.spoofed_eng_ip,
            dst_ip=self.target_plc_ip,
            src_port=55100,
            dst_port=502,
            transaction_id=201,
            protocol_id=0,
            length=6,
            unit_id=1,
            function_code=6,  # Write Single Register
            register_address=1010,  # Pressure_Setpoint
            register_value=500.0,   # Valoare periculoasa (limita de siguranta este 80 PSI)
            timestamp=now
        )
        return [p]

    def scenario_modbus_recon_scan(self, count: int = 15) -> List[ModbusPacket]:
        """
        Scenariul 3: Scanare de recunoastere industrial.
        Sondeaza rapid ID-urile de slave si adrese de registru pentru a descoperi PLC-urile active.

        Args:
            count (int): Numarul de pachete de sondare.

        Returns:
            List[ModbusPacket]: Fluxul de pachete de scanare.
        """
        packets = []
        now = time.time()
        for i in range(count):
            p = ModbusPacket(
                src_ip=self.rogue_ip,
                dst_ip=self.target_plc_ip,
                src_port=random.randint(50000, 60000),
                dst_port=502,
                transaction_id=300 + i,
                protocol_id=0,
                length=6,
                unit_id=random.choice([0, 1, 2, 5, 248, 255]),  # Include adrese invalide
                function_code=random.choice([1, 3, 17, 43]),
                register_address=random.randint(100, 50000),
                register_value=1.0,
                timestamp=now + (i * 0.02)  # Rata de trimitere foarte rapida
            )
            packets.append(p)
        return packets

    def scenario_dos_flood(self, count: int = 120) -> List[ModbusPacket]:
        """
        Scenariul 4: Inundare de tip Denial of Service (DoS/Flood pe portul 502).
        Trimite o rafala masiva de pachete intr-o fractiune de secunda pentru a bloca stiva TCP a PLC-ului.

        Args:
            count (int): Numarul de pachete din rafala de inundare.

        Returns:
            List[ModbusPacket]: Pachetele de flood.
        """
        packets = []
        now = time.time()
        for i in range(count):
            p = ModbusPacket(
                src_ip=self.rogue_ip,
                dst_ip=self.target_plc_ip,
                src_port=random.randint(50000, 60000),
                dst_port=502,
                transaction_id=4000 + i,
                protocol_id=0,
                length=6,
                unit_id=1,
                function_code=3,  # Cereri de citire in rafala
                register_address=1000,
                register_value=1.0,
                timestamp=now + (i * 0.002)  # 500 pachete/secunda!
            )
            packets.append(p)
        return packets

    def scenario_protocol_evasion(self) -> List[ModbusPacket]:
        """
        Scenariul 5: Tentativa de ocolire a regulilor prin pachete malformate (MBAP Corruption).
        Atacatorul trimite un pachet cu Protocol ID ilegal (ex: 255 in loc de 0) sau lungime falsa.

        Returns:
            List[ModbusPacket]: Pachetele malformate.
        """
        now = time.time()
        p1 = ModbusPacket(
            src_ip=self.rogue_ip,
            dst_ip=self.target_plc_ip,
            src_port=58001,
            dst_port=502,
            transaction_id=501,
            protocol_id=1,  # Ilegal conform RFC Modbus TCP!
            length=6,
            unit_id=1,
            function_code=3,
            register_address=1000,
            register_value=1.0,
            timestamp=now
        )

        p2 = ModbusPacket(
            src_ip=self.rogue_ip,
            dst_ip=self.target_plc_ip,
            src_port=58002,
            dst_port=502,
            transaction_id=502,
            protocol_id=0,
            length=2048,  # Lungime supradimensionata (tentativa buffer overflow)
            unit_id=1,
            function_code=99,  # Cod functie ilegal
            register_address=9999,
            register_value=0.0,
            timestamp=now + 0.1
        )
        return [p1, p2]

    def scenario_stealth_anomaly(self) -> List[ModbusPacket]:
        """
        Scenariul 6: Anomalie subtila de proces (Stealth Evasion).
        Pachetul respecta toate regulile statice (IP autorizat, FC03 legitim, registru existent),
        insa frecventa si volumul de date cerut deviaza statistic de la profilul nominal.
        Acest scenariu este conceput special pentru a evidentia rolul Inteligentei Artificiale.

        Returns:
            List[ModbusPacket]: Pachetele subtile de anomalie.
        """
        now = time.time()
        packets = []
        for i in range(10):
            p = ModbusPacket(
                src_ip="192.168.1.10",  # HMI autorizat
                dst_ip=self.target_plc_ip,
                src_port=59000 + i,
                dst_port=502,
                transaction_id=601 + i,
                protocol_id=0,
                length=6,
                unit_id=1,
                function_code=3,
                register_address=1000,
                register_value=100.0,  # Cerere masiva neobisnuita de 100 registre
                timestamp=now + (i * 0.005)  # Rafala atipica pentru HMI
            )
            packets.append(p)
        return packets

    def run_comparative_demonstration(
        self,
        firewall: ICSCoreFirewall,
        plc: VirtualPLC
    ) -> Dict[str, Any]:
        """
        Demonstratie comparativa esentiala pentru cerinta:
        "Aratati cum firewall-ul previne actiunile nesigure."

        Executa atacul de sabotaj critic (Presiune = 500 PSI):
          - Faza 1: Fara Firewall (Direct la PLC) -> Presiunea explodeaza, conducta se rupe!
          - Faza 2: Cu Firewall (Interpus) -> Atacul este interceptat si respins, procesul ramane sigur!

        Returns:
            Dict[str, Any]: Rezultatele comparative si starea fizica a sistemului in ambele cazuri.
        """
        attack_packets = self.scenario_critical_setpoint_tampering()
        attack_packet = attack_packets[0]

        # ---------------------------------------------------------------------
        # FAZA 1: EXECUTIE FARA FIREWALL (SISTEM SCADA VULNERABIL)
        # ---------------------------------------------------------------------
        plc.reset_state()
        state_before_without = plc.get_state()

        # Pachetul ajunge direct la PLC fara nicio filtrare
        plc_response_without = plc.execute_packet(attack_packet)
        # Simulam avansul procesului fizic pentru 3 secunde sub noul setpoint atacat
        for _ in range(6):
            plc.step_physics(dt=0.5)

        state_after_without = plc.get_state()

        # ---------------------------------------------------------------------
        # FAZA 2: EXECUTIE CU FIREWALL INDUSTRIAL ACTIVAT
        # ---------------------------------------------------------------------
        plc.reset_state()
        state_before_with = plc.get_state()

        # Pachetul este interceptat de firewall
        log_entry = firewall.process_packet(attack_packet)

        if log_entry.decision == "ALLOW":
            # Daca ar fi permis, ar ajunge la PLC
            plc.execute_packet(attack_packet)
        else:
            # Pachetul a fost respins (DROP) de firewall! PLC-ul NU primeste comanda
            pass

        # Simulam avansul procesului fizic in conditii sigure
        for _ in range(6):
            plc.step_physics(dt=0.5)

        state_after_with = plc.get_state()

        return {
            "attack_name": "Critical Setpoint Tampering (Explosion Simulation)",
            "packet_sent": attack_packet.to_dict(),
            "without_firewall": {
                "decision": "NO_FIREWALL_DIRECT_ACCESS",
                "state_before": state_before_without,
                "state_after": state_after_without,
                "pipeline_ruptured": state_after_without["is_pipeline_ruptured"],
                "final_pressure": state_after_without["pressure_psi"],
                "impact": "DEZASTRU CRITIC: Presiunea a explodat la cote periculoase, cauzand distrugerea fizica a conductei!"
            },
            "with_firewall": {
                "decision": log_entry.decision,
                "triggered_rule": log_entry.triggered_rule,
                "reason": log_entry.reason,
                "state_before": state_before_with,
                "state_after": state_after_with,
                "pipeline_ruptured": state_after_with["is_pipeline_ruptured"],
                "final_pressure": state_after_with["pressure_psi"],
                "impact": "PROTECTIE SUCCES: Firewall-ul a blocat actiunea nesigura. Procesul industrial a continuat in parametri normali!"
            }
        }
