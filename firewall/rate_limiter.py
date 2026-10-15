"""
=============================================================================
MODUL: firewall/rate_limiter.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Implementeaza un mecanism de limitare a ratei de transfer (Rate Limiter) bazat pe
    algoritmul Token Bucket pentru protectia echipamentelor industriale de joasa
    putere de calcul (PLC / RTU) impotriva atacurilor de tip Denial of Service (DoS/Flood).

    In retelele SCADA, un controler industrial (ex: Siemens S7-1200, Schneider Modicon)
    dispune de stive TCP/IP cu buffere limitate (adesea 8-16 conexiuni simultane).
    O inundare cu comenzi Modbus poate provoca "Denial of Control" si deconectarea
    de la bucla de control in timp real.
=============================================================================
"""

import time
from typing import Dict, Tuple


class TokenBucketRateLimiter:
    """
    Limitator de rata cu galeata de jetoane (Token Bucket) per adresa IP sursa.
    """

    def __init__(self, rate: float = 50.0, burst: int = 70):
        """
        Constructor pentru initializarea limitatorului de rata.

        Args:
            rate (float): Numarul de jetoane adaugate pe secunda (rata medie de pachete permise).
            burst (int): Capacitatea maxima a galetii (permite rafale scurte legitime).
        """
        self.rate = float(rate)
        self.burst = float(burst)

        # Retine starea galetii pentru fiecare IP: {ip: (current_tokens, last_update_timestamp)}
        self.buckets: Dict[str, Tuple[float, float]] = {}

        # Contor de atacuri DoS blocate per IP
        self.blocked_counts: Dict[str, int] = {}

    def check_and_consume(self, ip: str, timestamp: float = None, tokens: float = 1.0) -> bool:
        """
        Verifica daca adresa IP are suficiente jetoane si consuma un jeton.

        Args:
            ip (str): Adresa IP sursa inspectata.
            timestamp (float, optional): Timestamp-ul pachetului. Daca e None, foloseste time.time().
            tokens (float): Numarul de jetoane cerute (implicit 1).

        Returns:
            bool: True daca pachetul este conform ratei, False daca depaseste limita (Flood/DoS).
        """
        now = timestamp if timestamp is not None else time.time()

        if ip not in self.buckets:
            # Initializam galeata pentru IP-ul nou cu numarul maxim de jetoane
            self.buckets[ip] = (self.burst - tokens, now)
            return True

        current_tokens, last_update = self.buckets[ip]

        # Calculam cate jetoane s-au regenerat in intervalul de timp scurs
        elapsed = max(0.0, now - last_update)
        current_tokens = min(self.burst, current_tokens + (elapsed * self.rate))

        if current_tokens >= tokens:
            # Exista suficiente jetoane: consumam si aprobam pachetul
            self.buckets[ip] = (current_tokens - tokens, now)
            return True
        else:
            # Galeata este goala: pachetul depaseste limita de rata admisa
            self.buckets[ip] = (current_tokens, now)
            self.blocked_counts[ip] = self.blocked_counts.get(ip, 0) + 1
            return False

    def get_blocked_count(self, ip: str) -> int:
        """
        Returneaza numarul total de pachete blocate de rate limiter pentru un anumit IP.

        Args:
            ip (str): Adresa IP.

        Returns:
            int: Numar de pachete respinse.
        """
        return self.blocked_counts.get(ip, 0)

    def reset(self):
        """
        Reseteaza starea tuturor galetilor si a statisticilor.
        """
        self.buckets.clear()
        self.blocked_counts.clear()
