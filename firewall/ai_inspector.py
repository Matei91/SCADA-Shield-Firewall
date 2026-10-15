"""
=============================================================================
MODUL: firewall/ai_inspector.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Componenta de Inteligenta Artificiala / Machine Learning pentru inspectia
    anomaliilor de trafic si a comportamentelor evazive (Zero-Day Detection).

    Motiveaza utilizarea AI in firewall-ul industrial:
      Regulile deterministice pot fi ocolite prin comenzi care respecta sintaxa
      protocolului (ex: coduri FC03 valide transmise la momente neobisnuite,
      rafale scurte sub pragul DoS, interogari statistice anormale sau
      combinatii de parametri atipice).

    Modulul combina:
      - Random Forest Classifier (Supervizat) pentru recunoasterea semnaturilor de atac.
      - Isolation Forest (Nesupervizat) pentru masurarea distantei fata de comportamentul
        nominal al retelei de proces.
=============================================================================
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass

from firewall.modbus_packet import ModbusPacket


@dataclass
class AIVerdict:
    """
    Rezultatul inspectiei AI asupra unui pachet.
    """
    is_anomaly: bool
    rf_attack_probability: float  # Probabilitate de atac (0.0 - 1.0)
    iso_anomaly_score: float      # Scor de anomalie nesupervizat (0.0 - 1.0)
    confidence: float             # Increderea generala in decizie
    suspected_label: str          # "NORMAL" sau "ATTACK"
    explanation: str              # Explicatie generata de AI pentru prezentare


class AITrafficInspector:
    """
    Inspector inteligent de trafic bazat pe modelele Machine Learning antrenate.
    """

    def __init__(self, models_dir: str = None, threshold: float = 0.65):
        """
        Incarca modelele Random Forest si Isolation Forest salvate.

        Args:
            models_dir (str, optional): Calea catre folderul 'models'.
            threshold (float): Pragul peste care probabilitatea este considerata atac cert.
        """
        if models_dir is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            models_dir = os.path.abspath(os.path.join(current_dir, "..", "models"))

        self.models_dir = models_dir
        self.threshold = threshold

        self.rf_model_path = os.path.join(models_dir, "ics_firewall_rf_model.joblib")
        self.iso_model_path = os.path.join(models_dir, "ics_firewall_iso_model.joblib")

        self.rf_model = None
        self.iso_model = None
        self.is_ready = False

        # Urmarire dinamica a istoricului per IP pentru calculul trasaturilor temporale
        self.last_packet_time: Dict[str, float] = {}

        self._load_models()

    def _load_models(self):
        """
        Incarca modelele serializate de pe disc daca sunt disponibile.
        """
        try:
            if os.path.exists(self.rf_model_path) and os.path.exists(self.iso_model_path):
                self.rf_model = joblib.load(self.rf_model_path)
                self.iso_model = joblib.load(self.iso_model_path)
                self.is_ready = True
            else:
                print(f"[!] Modelele AI nu au fost gasite in {self.models_dir}. Rulati models/train_ai.py!")
        except Exception as e:
            print(f"[!] Eroare la incarcarea modelelor AI: {e}")
            self.is_ready = False

    def extract_packet_features(self, packet: ModbusPacket) -> np.ndarray:
        """
        Extrage vectorul de 9 trasaturi numerice necesar modelelor scikit-learn.

        Ordinea trasaturilor trebuie sa corespunda exact cu FEATURE_COLUMNS din train_ai.py:
          [function_code, register_address, register_value, inter_arrival_time,
           packet_rate, length, is_write_op, is_known_ip, is_critical_reg]

        Args:
            packet (ModbusPacket): Pachetul curent inspectat.

        Returns:
            np.ndarray: Vectorul 1D de trasaturi.
        """
        now = packet.timestamp
        prev_time = self.last_packet_time.get(packet.src_ip, now - 0.25)
        dt = max(0.0001, now - prev_time)
        self.last_packet_time[packet.src_ip] = now

        rate = round(1.0 / dt, 2)
        is_write = 1 if packet.is_write_operation else 0
        is_known = 1 if packet.src_ip in ["192.168.1.10", "192.168.1.20", "192.168.1.30"] else 0
        is_critical = 1 if (2000 <= packet.register_address <= 2010 or 1010 <= packet.register_address <= 1011) else 0

        features = [
            float(packet.function_code),
            float(packet.register_address),
            float(packet.register_value),
            float(dt),
            float(rate),
            float(packet.length),
            float(is_write),
            float(is_known),
            float(is_critical)
        ]

        return np.array(features).reshape(1, -1)

    def inspect_packet(self, packet: ModbusPacket) -> AIVerdict:
        """
        Evalueaza pachetul utilizand ansamblul de inteligenta artificiala.

        Args:
            packet (ModbusPacket): Pachetul de evaluat.

        Returns:
            AIVerdict: Verdictul analizei AI.
        """
        if not self.is_ready:
            # Daca modelul nu e incarcat, consideram pachetul ca fiind neutru
            return AIVerdict(
                is_anomaly=False,
                rf_attack_probability=0.0,
                iso_anomaly_score=0.0,
                confidence=0.5,
                suspected_label="NORMAL",
                explanation="Modulul AI nu este initializat sau incarcat."
            )

        X = self.extract_packet_features(packet)

        # 1. Predictie Random Forest
        rf_probs = self.rf_model.predict_proba(X)[0]
        attack_prob = float(rf_probs[1]) if len(rf_probs) > 1 else float(rf_probs[0])

        # 2. Scor Anomaly Isolation Forest
        # decision_function returneaza valori negative pentru anomalii (cu cat e mai negativ, cu atat e mai anormal)
        iso_raw_score = float(self.iso_model.decision_function(X)[0])
        # Normalizam scorul intr-o scara intuitiva [0.0, 1.0] unde 1.0 = anomalie extrema
        iso_score = round(max(0.0, min(1.0, 0.5 - (iso_raw_score * 2.0))), 3)

        # Decizie combinata
        is_anomaly = (attack_prob >= self.threshold) or (iso_score >= 0.70)
        suspected_label = "ATTACK" if is_anomaly else "NORMAL"
        confidence = round(max(attack_prob, 1.0 - attack_prob), 3)

        # Generare explicatie detaliata pentru auditor/prezentare
        if is_anomaly:
            if attack_prob >= self.threshold:
                explanation = (
                    f"Modelul AI (Random Forest) a detectat semnatura de amenintare industriala cu "
                    f"certitudine de {attack_prob * 100:.1f}%. Parametri atipici: FC={packet.function_code}, "
                    f"Addr={packet.register_address}, Val={packet.register_value}."
                )
            else:
                explanation = (
                    f"Modelul AI (Isolation Forest) a detectat o anomalie comportamentala statistica "
                    f"(Scor Deviatie = {iso_score:.2f}). Pachetul deviaza semnificativ de la tiparul nominal SCADA."
                )
        else:
            explanation = (
                f"Modelul AI a confirmat ca pachetul se incadreaza in profilul statistic normal "
                f"de telemetrie industriala (Incredere = {confidence * 100:.1f}%)."
            )

        return AIVerdict(
            is_anomaly=is_anomaly,
            rf_attack_probability=round(attack_prob, 4),
            iso_anomaly_score=iso_score,
            confidence=confidence,
            suspected_label=suspected_label,
            explanation=explanation
        )
