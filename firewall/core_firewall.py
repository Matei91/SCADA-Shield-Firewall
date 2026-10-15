"""
=============================================================================
MODUL: firewall/core_firewall.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Arhitectura centrala a firewall-ului industrial hibrid (SCADA-Shield).
    Integreaza toate mecanismele de protectie intr-o solutie unificata:
      1. Inspectie de Rata (Rate Limiter / Anti-Flood DoS pe portul 502)
      2. Inspectie Profunda Deterministica (DPI Rule Engine: L3/L4/L7, Read-Only,
         Boundary Checks, Validare Limite Proces Fizic)
      3. Inspectie Inteligenta Bazata pe AI (Random Forest + Isolation Forest)
      4. Subsistem de Audit & Jurnalizare Securizata (SIEM Ready Logging)

    Ofera o imagine clara a modului in care actiunile nesigure si tentativele de
    sabotaj industrial sunt prevenite inainte de a atinge controlerul logic programabil (PLC).
=============================================================================
"""

import time
import pandas as pd
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from firewall.modbus_packet import ModbusPacket
from firewall.rate_limiter import TokenBucketRateLimiter
from firewall.rule_engine import ICSFirewallRuleEngine, RuleVerdict
from firewall.ai_inspector import AITrafficInspector, AIVerdict


@dataclass
class FirewallLogEntry:
    """
    Inregistrare completa de audit pentru fiecare pachet inspectat.
    """
    id: int
    timestamp: float
    datetime_str: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    unit_id: int
    function_code: int
    function_name: str
    register_address: int
    register_value: float
    decision: str              # "ALLOW" sau "DROP"
    triggered_rule: str        # ID-ul regulii sau "AI_ANOMALY_DETECTOR"
    reason: str                # Explicatia umana detaliata a deciziei
    ai_anomaly: bool           # Daca AI-ul a identificat anomalie
    ai_attack_prob: float      # Probabilitatea calculata de AI
    severity: str              # "INFO", "WARNING", "CRITICAL"


class ICSCoreFirewall:
    """
    Clasa principala a firewall-ului industrial hibrid.
    """

    def __init__(
        self,
        rules_path: Optional[str] = None,
        limits_path: Optional[str] = None,
        models_dir: Optional[str] = None
    ):
        """
        Initializeaza toate subsistemele firewall-ului.
        """
        # 1. Motor de reguli DPI
        self.rule_engine = ICSFirewallRuleEngine(rules_path, limits_path)

        # 2. Limitator de rata anti-DoS (max 50 req/sec cu rafala de 70)
        self.rate_limiter = TokenBucketRateLimiter(rate=50.0, burst=70)

        # 3. Modul de inteligenta artificiala
        self.ai_inspector = AITrafficInspector(models_dir, threshold=self.rule_engine.ai_anomaly_threshold)

        # 4. Jurnalizare si metrici in timp real
        self.logs: List[FirewallLogEntry] = []
        self._log_counter = 0

        # Statistici
        self.stats = {
            "total_packets": 0,
            "allowed_packets": 0,
            "dropped_packets": 0,
            "ai_anomalies_detected": 0,
            "rule_drops_breakdown": {},
            "severity_breakdown": {"INFO": 0, "WARNING": 0, "CRITICAL": 0}
        }

    @property
    def read_only_mode(self) -> bool:
        """
        Indica daca este activ regimul Read-Only.
        """
        return self.rule_engine.read_only_mode

    @read_only_mode.setter
    def read_only_mode(self, value: bool):
        """
        Comuta regimul Read-Only.
        """
        self.rule_engine.set_read_only_mode(value)

    def process_packet(self, packet: ModbusPacket) -> FirewallLogEntry:
        """
        Proceseaza un pachet prin intregul lant de protectie.

        Fluxul de executie:
          Pas 1: Verificare Anti-DoS (Rate Limiter)
          Pas 2: Verificare Reguli DPI Deterministe (Protocol, IP, Read-Only, Limite Proces)
          Pas 3: Inspectie de Comportament AI (daca a trecut de reguli si AI e activat)
          Pas 4: Jurnalizare si actualizare metrici

        Args:
            packet (ModbusPacket): Pachetul de inspectat.

        Returns:
            FirewallLogEntry: Intrarea completa de log generata.
        """
        self._log_counter += 1
        self.stats["total_packets"] += 1
        now_ts = packet.timestamp

        decision = "ALLOW"
        triggered_rule = "R000_POLICY_ALLOW"
        reason = "Pachet conform politicii de securitate industriale."
        severity = "INFO"
        ai_anomaly = False
        ai_prob = 0.0

        # ---------------------------------------------------------------------
        # PASUL 1: VERIFICARE RATE LIMITER (ANTI-FLOOD / DoS)
        # ---------------------------------------------------------------------
        if not self.rate_limiter.check_and_consume(packet.src_ip, timestamp=now_ts):
            decision = "DROP"
            triggered_rule = "R006_RATE_LIMIT"
            reason = f"Atac de tip Denial of Service (DoS/Flood) detectat de la {packet.src_ip}! Rata depaseste 50 pachete/sec."
            severity = "CRITICAL"

        # ---------------------------------------------------------------------
        # PASUL 2: VERIFICARE REGULI DETERMINISTICE DPI
        # ---------------------------------------------------------------------
        if decision == "ALLOW":
            rule_verdict: RuleVerdict = self.rule_engine.evaluate_packet(packet)
            if not rule_verdict.allowed:
                decision = rule_verdict.action
                triggered_rule = rule_verdict.rule_id
                reason = rule_verdict.reason
                severity = rule_verdict.severity

        # ---------------------------------------------------------------------
        # PASUL 3: INSPECTIE COMPORTAMENTALA AI (MACHINE LEARNING)
        # ---------------------------------------------------------------------
        # Chiar daca un pachet trece de regulile statice, AI-ul inspecteaza daca exista
        # tentative de ocolire / comportament atipic de proces
        if self.rule_engine.ai_inspection_enabled:
            ai_verdict: AIVerdict = self.ai_inspector.inspect_packet(packet)
            ai_anomaly = ai_verdict.is_anomaly
            ai_prob = ai_verdict.rf_attack_probability

            if ai_anomaly:
                self.stats["ai_anomalies_detected"] += 1
                # Daca pachetul ar fi fost permis de reguli statice, AI-ul il blocheaza
                # pentru a preveni evaziunea (Zero-Day Protection)
                if decision == "ALLOW":
                    decision = "DROP"
                    triggered_rule = "R_AI_ANOMALY_EVASION"
                    reason = f"[BLOCAT DE INTELIGENTA ARTIFICIALA] {ai_verdict.explanation}"
                    severity = "CRITICAL"

        # ---------------------------------------------------------------------
        # PASUL 4: ACTUALIZARE STATISTICI SI AUDIT
        # ---------------------------------------------------------------------
        if decision == "ALLOW":
            self.stats["allowed_packets"] += 1
        else:
            self.stats["dropped_packets"] += 1
            self.stats["rule_drops_breakdown"][triggered_rule] = (
                self.stats["rule_drops_breakdown"].get(triggered_rule, 0) + 1
            )

        self.stats["severity_breakdown"][severity] = (
            self.stats["severity_breakdown"].get(severity, 0) + 1
        )

        dt_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now_ts))

        log_entry = FirewallLogEntry(
            id=self._log_counter,
            timestamp=now_ts,
            datetime_str=dt_str,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            unit_id=packet.unit_id,
            function_code=packet.function_code,
            function_name=packet.get_function_name(),
            register_address=packet.register_address,
            register_value=packet.register_value,
            decision=decision,
            triggered_rule=triggered_rule,
            reason=reason,
            ai_anomaly=ai_anomaly,
            ai_attack_prob=ai_prob,
            severity=severity
        )

        self.logs.append(log_entry)
        return log_entry

    def get_metrics(self) -> Dict[str, Any]:
        """
        Returneaza o sinteza a metricilor operationale ale firewall-ului.
        """
        total = self.stats["total_packets"]
        dropped = self.stats["dropped_packets"]
        allowed = self.stats["allowed_packets"]

        drop_rate = round((dropped / total * 100), 2) if total > 0 else 0.0

        return {
            "total_inspected": total,
            "allowed": allowed,
            "dropped": dropped,
            "drop_rate_pct": drop_rate,
            "ai_anomalies": self.stats["ai_anomalies_detected"],
            "read_only_mode": self.read_only_mode,
            "rules_breakdown": self.stats["rule_drops_breakdown"],
            "severity_breakdown": self.stats["severity_breakdown"]
        }

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Returneaza cele mai recente inregistrari de audit.
        """
        return [asdict(entry) for entry in self.logs[-limit:]]

    def export_logs_to_dataframe(self) -> pd.DataFrame:
        """
        Exporta istoricul complet de loguri ca DataFrame pandas.
        """
        return pd.DataFrame([asdict(entry) for entry in self.logs])

    def reset(self):
        """
        Reseteaza starea, contoarele si istoricul firewall-ului.
        """
        self.logs.clear()
        self._log_counter = 0
        self.rate_limiter.reset()
        self.stats = {
            "total_packets": 0,
            "allowed_packets": 0,
            "dropped_packets": 0,
            "ai_anomalies_detected": 0,
            "rule_drops_breakdown": {},
            "severity_breakdown": {"INFO": 0, "WARNING": 0, "CRITICAL": 0}
        }
