"""
=============================================================================
MODUL: firewall/rule_engine.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Motorul de reguli deterministice cu inspectie profunda a pachetelor (DPI - Deep
    Packet Inspection) pentru protocolul industrial Modbus TCP.

    Inspecteaza atat metadatele din antete (Layer 3/4: IP sursa, porturi; Layer 7:
    Protocol ID, Unit ID, Function Code), cat si semantica aplicatiei industriale:
      - Regimul "Read-Only Enforcement" (permite exclusiv citirea de telemetrie)
      - Whitelisting pe adrese IP industriale (Purdue Level 2/1)
      - Protectia registrelor critice de securitate (Coils de oprire urgenta)
      - Validarea limitelor fizice ale procesului (Semantic Payload Verification:
        prevenirea scrierii unor valori periculoase de presiune, temperatura sau turatie).
=============================================================================
"""

import os
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from firewall.modbus_packet import ModbusPacket, WRITE_FUNCTION_CODES, READ_FUNCTION_CODES


@dataclass
class RuleVerdict:
    """
    Rezultatul inspectiei unei reguli aplicate asupra unui pachet.
    """
    allowed: bool
    action: str              # "ALLOW", "DROP", "ALERT"
    rule_id: str             # Identificatorul regulii declansate (ex: "R003_READ_ONLY")
    reason: str              # Explicatie detaliata in limba romana pentru prezentare
    severity: str = "INFO"   # "INFO", "WARNING", "CRITICAL"


class ICSFirewallRuleEngine:
    """
    Motorul principal de executie si validare a politicilor de securitate industriala.
    """

    def __init__(self, rules_config_path: str = None, limits_config_path: str = None):
        """
        Initializeaza motorul de reguli incarcand fisierele de configurare JSON.

        Args:
            rules_config_path (str, optional): Calea catre firewall_rules.json
            limits_config_path (str, optional): Calea catre industrial_limits.json
        """
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(current_dir, ".."))

        if rules_config_path is None:
            rules_config_path = os.path.join(project_root, "config", "firewall_rules.json")
        if limits_config_path is None:
            limits_config_path = os.path.join(project_root, "config", "industrial_limits.json")

        self.rules_config_path = rules_config_path
        self.limits_config_path = limits_config_path

        # Incarcam politicile
        self.rules_data = self._load_json(rules_config_path)
        self.limits_data = self._load_json(limits_config_path)

        # Stari comutabile direct din UI / Dashboard
        self.read_only_mode = self.rules_data.get("read_only_mode", True)
        self.ai_inspection_enabled = self.rules_data.get("ai_inspection_enabled", True)
        self.ai_anomaly_threshold = self.rules_data.get("ai_anomaly_threshold", 0.65)

        # Liste si limite extrase
        self.ip_whitelist = set(self._extract_whitelist_ips())
        self.industrial_limits = self.limits_data.get("registers", {})

    def _load_json(self, path: str) -> Dict[str, Any]:
        """
        Incarca in siguranta un fisier JSON de pe disc.
        """
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _extract_whitelist_ips(self) -> List[str]:
        """
        Extrage lista de IP-uri autorizate din regulile configurate.
        """
        for r in self.rules_data.get("rules", []):
            if r.get("id") == "R002_IP_WHITELIST":
                return r.get("match", {}).get("src_ip_not_in", [])
        return ["192.168.1.10", "192.168.1.20", "192.168.1.30"]

    def set_read_only_mode(self, enabled: bool):
        """
        Activeaza sau dezactiveaza regimul strict Read-Only.
        """
        self.read_only_mode = enabled

    def add_whitelist_ip(self, ip: str):
        """
        Adauga un nou IP in lista alba de statii industriale autorizate.
        """
        self.ip_whitelist.add(ip)

    def remove_whitelist_ip(self, ip: str):
        """
        Elimina un IP din lista alba.
        """
        self.ip_whitelist.discard(ip)

    def evaluate_packet(self, packet: ModbusPacket) -> RuleVerdict:
        """
        Inspecteaza profund (DPI) pachetul Modbus TCP conform ierarhiei de securitate SCADA.

        Secventa de verificare:
          1. Sanitizare protocol MBAP (Protocol ID != 0, Slave ID invalid)
          2. Whitelist adrese IP (Purdue Level 2 - separare retea HMI/PLC)
          3. Read-Only Enforcement (Blocare FC05/FC06/FC15/FC16)
          4. Restrictie pe roluri (Doar statia de inginerie poate trimite comenzi)
          5. Protectia registrelor critice de urgenta (Coils 2000-2010)
          6. Verificarea limitelor fizice de proces (Sanity check valori presiune/temperatura)

        Args:
            packet (ModbusPacket): Obiectul pachet Modbus TCP decodificat.

        Returns:
            RuleVerdict: Rezultatul deciziei de filtrare cu motivatie clara.
        """
        # ---------------------------------------------------------------------
        # REGULA 1: SANITIZARE PROTOCOL MODBUS TCP (R001)
        # ---------------------------------------------------------------------
        if packet.protocol_id != 0:
            return RuleVerdict(
                allowed=False,
                action="DROP",
                rule_id="R001_PROTO_SANITATION",
                reason=f"Campul Protocol ID din antetul MBAP este {packet.protocol_id} (trebuie sa fie 0x0000 conform specificatiei Modbus TCP). Posibil atac de evaziune.",
                severity="CRITICAL"
            )

        if packet.unit_id < 1 or packet.unit_id > 247:
            return RuleVerdict(
                allowed=False,
                action="DROP",
                rule_id="R001_PROTO_SANITATION",
                reason=f"Adresa de slave (Unit ID = {packet.unit_id}) se afla in afara intervalului valid industrial [1, 247]. Posibila scanare de retea.",
                severity="WARNING"
            )

        # ---------------------------------------------------------------------
        # REGULA 2: CONTROLUL ACCESULUI PRIN WHITELIST IP (R002)
        # ---------------------------------------------------------------------
        if packet.src_ip not in self.ip_whitelist:
            return RuleVerdict(
                allowed=False,
                action="DROP",
                rule_id="R002_IP_WHITELIST",
                reason=f"Adresa IP sursa {packet.src_ip} nu face parte din lista alba a statiilor SCADA autorizate (HMI, Engineering, Historian).",
                severity="CRITICAL"
            )

        # ---------------------------------------------------------------------
        # REGULA 3: ENFORCEMENT REGIM READ-ONLY (R003)
        # ---------------------------------------------------------------------
        # Daca este activ regimul Read-Only, se blocheaza orice operatiune de scriere
        if self.read_only_mode and packet.is_write_operation:
            return RuleVerdict(
                allowed=False,
                action="DROP",
                rule_id="R003_READ_ONLY_ENFORCEMENT",
                reason=f"Regimul 'Read-Only' este activat! Comanda {packet.get_function_name()} a fost respinsa pentru a proteja procesul fizic.",
                severity="WARNING"
            )

        # ---------------------------------------------------------------------
        # REGULA 4: RESTRICTIE ROL STATII PENTRU SCRIERE
        # ---------------------------------------------------------------------
        # Chiar daca modul read_only este dezactivat, HMI-ul obisnuit (192.168.1.10)
        # are doar rol de monitorizare; doar statia de inginerie (192.168.1.20) are drept de scriere.
        if packet.is_write_operation and packet.src_ip != "192.168.1.20":
            return RuleVerdict(
                allowed=False,
                action="DROP",
                rule_id="R004_ROLE_RBAC_VIOLATION",
                reason=f"Statia {packet.src_ip} (Operator HMI) nu are privilegii de scriere. Doar Statia de Inginerie (192.168.1.20) este autorizata.",
                severity="WARNING"
            )

        # ---------------------------------------------------------------------
        # REGULA 5: PROTECTIE REGISTRE CRITICE DE SECURITATE (R005)
        # ---------------------------------------------------------------------
        # Registrele 2000-2010 sunt valve de urgenta / shutoff
        if 2000 <= packet.register_address <= 2010 and packet.is_write_operation:
            return RuleVerdict(
                allowed=False,
                action="DROP",
                rule_id="R005_CRITICAL_REGISTER_PROTECTION",
                reason=f"Tentativa de scriere in registrul de siguranta critica {packet.register_address} (Valva Oprire Urgenta). Actiune interzisa prin politica de siguranta.",
                severity="CRITICAL"
            )

        # ---------------------------------------------------------------------
        # REGULA 6: VALIDARE SEMANTICA A LIMITELOR FIZICE (R006 - Deep Safety)
        # ---------------------------------------------------------------------
        # Daca se scrie intr-un registru cunoscut de proces, verificam daca valoarea este sigura
        reg_str = str(packet.register_address)
        if packet.is_write_operation and reg_str in self.industrial_limits:
            limit_info = self.industrial_limits[reg_str]
            min_val = limit_info.get("min_safe", float("-inf"))
            max_val = limit_info.get("max_safe", float("inf"))
            val = packet.register_value

            if val < min_val or val > max_val:
                return RuleVerdict(
                    allowed=False,
                    action="DROP",
                    rule_id="R006_PHYSICAL_LIMITS_VIOLATION",
                    reason=(
                        f"Violare a sigurantei procesului fizic! Valoarea ceruta {val} {limit_info.get('unit', '')} "
                        f"pentru parametrul '{limit_info.get('name', '')}' depaseste limitele sigure de exploatare "
                        f"[{min_val}, {max_val}]. Risc de explozie sau avarie majora a conductei de gaz!"
                    ),
                    severity="CRITICAL"
                )

        # Daca toate regulile deterministice sunt indeplinite, pachetul este permis
        return RuleVerdict(
            allowed=True,
            action="ALLOW",
            rule_id="R000_POLICY_ALLOW",
            reason=f"Pachet Modbus TCP conform politicii de securitate industriale: {packet.get_function_name()}.",
            severity="INFO"
        )
