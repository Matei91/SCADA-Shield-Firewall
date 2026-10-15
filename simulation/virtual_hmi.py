"""
=============================================================================
MODUL: simulation/virtual_hmi.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Simuleaza comportamentul legitim al unei statii HMI (Human Machine Interface)
    si al unei statii de inginerie intr-un mediu operational SCADA.

    Genereaza secvente de pachete de telemetrie si comenzi de mentenanta autorizate:
      - Poling ciclic HMI (FC 03 / FC 01) la fiecare 200-500ms
      - Cereri de status de la statia de arhivare (Historian)
      - Comenzi autorizate de ajustare a setpoint-ului de la statia de inginerie
=============================================================================
"""

import time
import random
from typing import List

from firewall.modbus_packet import ModbusPacket


class VirtualHMI:
    """
    Simulator de statie HMI / SCADA Client legitim.
    """

    def __init__(self, hmi_ip: str = "192.168.1.10", plc_ip: str = "192.168.1.50"):
        """
        Initializeaza clientul HMI legitim.

        Args:
            hmi_ip (str): Adresa IP a statiei HMI operator.
            plc_ip (str): Adresa IP a PLC-ului tinta.
        """
        self.hmi_ip = hmi_ip
        self.plc_ip = plc_ip
        self.tx_id = 1

    def generate_telemetry_poll(self) -> ModbusPacket:
        """
        Genereaza o cerere ciclica legitima de citire a telemetriei procesului (FC 03).

        Returns:
            ModbusPacket: Pachet Modbus TCP de citire a registrelor de senzori.
        """
        packet = ModbusPacket(
            src_ip=self.hmi_ip,
            dst_ip=self.plc_ip,
            src_port=random.randint(50000, 60000),
            dst_port=502,
            transaction_id=self.tx_id,
            protocol_id=0,
            length=6,
            unit_id=1,
            function_code=3,  # Read Holding Registers
            register_address=1000,
            register_value=4,  # Cere citirea a 4 registre consecutive
            timestamp=time.time()
        )
        self.tx_id = (self.tx_id + 1) % 65535
        return packet

    def generate_valve_status_poll(self) -> ModbusPacket:
        """
        Genereaza o cerere legitima de verificare a starii valvelor (FC 01 - Read Coils).

        Returns:
            ModbusPacket: Pachet de citire a bobinelor de comanda.
        """
        packet = ModbusPacket(
            src_ip=self.hmi_ip,
            dst_ip=self.plc_ip,
            src_port=random.randint(50000, 60000),
            dst_port=502,
            transaction_id=self.tx_id,
            protocol_id=0,
            length=6,
            unit_id=1,
            function_code=1,  # Read Coils
            register_address=2001,
            register_value=2,
            timestamp=time.time()
        )
        self.tx_id = (self.tx_id + 1) % 65535
        return packet

    def generate_legitimate_setpoint_adjustment(self, target_psi: float = 55.0) -> ModbusPacket:
        """
        Genereaza o comanda legitima de reglare a presiunii din partea statiei de inginerie.

        Args:
            target_psi (float): Noua valoare de referinta (trebuie sa fie in intervalul [20, 80]).

        Returns:
            ModbusPacket: Comanda de scriere FC 06 autorizata.
        """
        eng_ip = "192.168.1.20"  # Statia de inginerie autorizata
        packet = ModbusPacket(
            src_ip=eng_ip,
            dst_ip=self.plc_ip,
            src_port=random.randint(50000, 60000),
            dst_port=502,
            transaction_id=self.tx_id,
            protocol_id=0,
            length=6,
            unit_id=1,
            function_code=6,  # Write Single Register
            register_address=1010,
            register_value=float(target_psi),
            timestamp=time.time()
        )
        self.tx_id = (self.tx_id + 1) % 65535
        return packet
