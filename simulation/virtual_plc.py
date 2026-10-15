"""
=============================================================================
MODUL: simulation/virtual_plc.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Simuleaza comportamentul intern si memoria unui Controler Logic Programabil (PLC)
    dintr-o statie de comprimare si transport a gazelor naturale.

    Caracteristici simulate:
      1. Tabela de registre Modbus (Coils & Holding Registers).
      2. Model fizic dinamic al procesului tehnologic (bucla de reglare a presiunii,
         temperatura compresorului, debitul de gaz in functie de turatia pompei).
      3. Indicatori de avarie fizica (ruptura conducta prin suprapresiune > 120 PSI,
         cavitatia pompei sau blocaj de siguranta).

    Permite demonstrarea vizuala a conceptului de "Cyber-Physical Attack":
      Daca un atac ajunge la PLC (fara firewall), procesul fizic este distrus.
      Daca atacul este blocat de firewall, parametrii fizici raman in domeniul sigur.
=============================================================================
"""

import time
import random
from typing import Dict, Any, Optional

from firewall.modbus_packet import ModbusPacket


class VirtualPLC:
    """
    Simulator de controler industrial Modbus TCP cu model fizic integrat.
    """

    def __init__(self, ip: str = "192.168.1.50", unit_id: int = 1):
        """
        Initializeaza PLC-ul cu parametrii nominali de exploatare.

        Args:
            ip (str): Adresa IP a controlerului industrial.
            unit_id (int): Slave ID-ul configurat in hardware.
        """
        self.ip = ip
        self.unit_id = unit_id

        # Tabela de registre Modbus (adresa -> valoare)
        self.holding_registers: Dict[int, float] = {
            1000: 50.0,    # Presiune linie masurata (PSI)
            1001: 250.0,   # Debit gaz masurat (m3/h)
            1002: 45.0,    # Temperatura compresor (Celsius)
            1010: 50.0,    # Setpoint presiune dorita (PSI) - sigur: 20-80
            1011: 1500.0   # Setpoint turatie pompa (RPM)   - sigur: 500-3000
        }

        self.coils: Dict[int, int] = {
            2001: 0,       # Valva Oprire Urgenta (0 = Deschis / Gazul circula, 1 = Izolat)
            2002: 0        # Valva Suprapresiune Relief (0 = Inchis, 1 = Descarcare)
        }

        # Starea de integritate a procesului fizic
        self.is_pipeline_ruptured = False
        self.is_emergency_shutdown = False
        self.last_update_time = time.time()

    def step_physics(self, dt: float = 0.5):
        """
        Avanseaza simularea ecuatiilor diferentiale ale procesului fizic de transport gaz.

        Args:
            dt (float): Pasul de timp al simularii (secunde).
        """
        setpoint = self.holding_registers[1010]
        current_p = self.holding_registers[1000]
        pump_rpm = self.holding_registers[1011]
        valve_closed = self.coils[2001]

        if valve_closed == 1:
            # Valva de urgenta a fost declansata: debitul scade la 0
            self.holding_registers[1001] = max(0.0, self.holding_registers[1001] - (20.0 * dt))
            self.is_emergency_shutdown = True
        else:
            self.is_emergency_shutdown = False
            # Presiunea tinde catre setpoint-ul comandat
            dp = (setpoint - current_p) * 0.15 * dt
            # Zgomot mic de masura pe senzor
            noise = random.uniform(-0.2, 0.2)
            self.holding_registers[1000] = round(max(0.0, current_p + dp + noise), 2)

            # Debitul depinde de turatia pompei si presiune
            target_flow = (pump_rpm / 1500.0) * 250.0
            self.holding_registers[1001] = round(target_flow + random.uniform(-1.0, 1.0), 1)

            # Temperatura compresorului creste proportional cu turatia
            target_temp = 35.0 + (pump_rpm / 3000.0) * 45.0
            cur_temp = self.holding_registers[1002]
            self.holding_registers[1002] = round(cur_temp + (target_temp - cur_temp) * 0.05 * dt, 1)

        # Verificam daca s-a produs o catastrofa fizica (suprapresiune extrema > 120 PSI)
        if self.holding_registers[1000] > 120.0:
            self.is_pipeline_ruptured = True

    def execute_packet(self, packet: ModbusPacket) -> Dict[str, Any]:
        """
        Executa pachetul Modbus receptionat pe controlerul fizic (cand este permis de firewall).

        Args:
            packet (ModbusPacket): Pachetul industrial sosit la portul 502.

        Returns:
            Dict[str, Any]: Raspunsul PLC-ului si starea actualizata a registrelor.
        """
        # Actualizam simularea fizica
        now = time.time()
        dt = max(0.1, min(2.0, now - self.last_update_time))
        self.step_physics(dt)
        self.last_update_time = now

        fc = packet.function_code
        addr = packet.register_address
        val = packet.register_value

        # ---------------------------------------------------------------------
        # COMANDA SCRIERE UN SINGUR REGISTRU (FC 06)
        # ---------------------------------------------------------------------
        if fc == 6:
            self.holding_registers[addr] = float(val)
            # Rulam un pas fizic pentru a reflecta comanda imediata
            self.step_physics(dt=1.0)
            return {
                "status": "SUCCESS",
                "message": f"Registrul {addr} a fost actualizat la valoarea {val}",
                "physical_state": self.get_state()
            }

        # ---------------------------------------------------------------------
        # COMANDA SCRIERE BOBINA / COIL (FC 05)
        # ---------------------------------------------------------------------
        elif fc == 5:
            # In Modbus standard, 0xFF00 reprezinta ON (1), 0x0000 reprezinta OFF (0)
            coil_state = 1 if val > 0 else 0
            self.coils[addr] = coil_state
            self.step_physics(dt=1.0)
            return {
                "status": "SUCCESS",
                "message": f"Bobina {addr} a fost comutata in starea {coil_state}",
                "physical_state": self.get_state()
            }

        # ---------------------------------------------------------------------
        # COMANDA CITIRE REGISTRE (FC 03 / FC 04)
        # ---------------------------------------------------------------------
        elif fc in [3, 4]:
            read_val = self.holding_registers.get(addr, 0.0)
            return {
                "status": "SUCCESS",
                "message": f"Citire registru {addr} = {read_val}",
                "data": {addr: read_val},
                "physical_state": self.get_state()
            }

        # ---------------------------------------------------------------------
        # COMANDA CITIRE BOBINE (FC 01 / FC 02)
        # ---------------------------------------------------------------------
        elif fc in [1, 2]:
            read_val = self.coils.get(addr, 0)
            return {
                "status": "SUCCESS",
                "message": f"Citire bobina {addr} = {read_val}",
                "data": {addr: read_val},
                "physical_state": self.get_state()
            }

        else:
            return {
                "status": "ERROR_EXCEPTION",
                "message": f"Cod de functie nesuportat sau ilegal (FC{fc})",
                "physical_state": self.get_state()
            }

    def get_state(self) -> Dict[str, Any]:
        """
        Returneaza starea completa a procesului fizic si a registrelor.

        Returns:
            Dict[str, Any]: Parametrii fizici actuali ai statiei SCADA.
        """
        return {
            "pressure_psi": self.holding_registers[1000],
            "flow_rate_m3h": self.holding_registers[1001],
            "compressor_temp_c": self.holding_registers[1002],
            "pressure_setpoint": self.holding_registers[1010],
            "pump_rpm_setpoint": self.holding_registers[1011],
            "emergency_valve_closed": self.coils[2001],
            "relief_vent_open": self.coils[2002],
            "is_pipeline_ruptured": self.is_pipeline_ruptured,
            "is_emergency_shutdown": self.is_emergency_shutdown
        }

    def reset_state(self):
        """
        Reseteaza PLC-ul si procesul fizic la starea nominala normala.
        """
        self.holding_registers = {
            1000: 50.0,
            1001: 250.0,
            1002: 45.0,
            1010: 50.0,
            1011: 1500.0
        }
        self.coils = {
            2001: 0,
            2002: 0
        }
        self.is_pipeline_ruptured = False
        self.is_emergency_shutdown = False
        self.last_update_time = time.time()
