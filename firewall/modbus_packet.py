"""
=============================================================================
MODUL: firewall/modbus_packet.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Implementeaza structura si decodarea pachetelor pentru protocolul industrial
    Modbus TCP (port 502).

    Un cadru Modbus TCP este compus din:
      1. MBAP Header (Modbus Application Protocol Header) - 7 octeti:
         - Transaction Identifier (2 octeti): Coreleaza cererea cu raspunsul.
         - Protocol Identifier (2 octeti): 0x0000 = Modbus protocol.
         - Length (2 octeti): Numarul de octeti ramasi (Unit ID + PDU).
         - Unit Identifier / Slave Address (1 octet): Adresa PLC/RTU (1..247).
      2. Modbus PDU (Protocol Data Unit):
         - Function Code (1 octet): Codul operatiunii (citire/scriere).
         - Data (variabil): Adresa registrului, numar de registre/bobine sau valorile de scris.

    Modulul ofera metode de parsare din octeti bruti (bytes) si de conversie
    in dictionare pentru inspectie DPI si clasificare AI.
=============================================================================
"""

import time
import struct
from typing import Dict, Any, Optional, Tuple


# Dictionar standard de coduri de functie Modbus si descrierea lor industriala
MODBUS_FUNCTION_NAMES = {
    1: "Read Coils (FC01)",
    2: "Read Discrete Inputs (FC02)",
    3: "Read Holding Registers (FC03)",
    4: "Read Input Registers (FC04)",
    5: "Write Single Coil (FC05)",
    6: "Write Single Register (FC06)",
    7: "Read Exception Status (FC07)",
    8: "Diagnostics (FC08)",
    11: "Get Comm Event Counter (FC11)",
    12: "Get Comm Event Log (FC12)",
    15: "Write Multiple Coils (FC15)",
    16: "Write Multiple Registers (FC16)",
    17: "Report Server ID (FC17)",
    22: "Mask Write Register (FC22)",
    23: "Read/Write Multiple Registers (FC23)",
    43: "Encapsulated Interface Transport (FC43)"
}

# Multimi pentru clasificare rapida citire vs scriere
WRITE_FUNCTION_CODES = {5, 6, 15, 16, 22, 23}
READ_FUNCTION_CODES = {1, 2, 3, 4}


class ModbusPacket:
    """
    Reprezinta un pachet Modbus TCP inspectat la nivelul Layer 3, 4 si Layer 7 (DPI).
    """

    def __init__(
        self,
        src_ip: str = "127.0.0.1",
        dst_ip: str = "127.0.0.1",
        src_port: int = 50000,
        dst_port: int = 502,
        transaction_id: int = 1,
        protocol_id: int = 0,
        length: int = 6,
        unit_id: int = 1,
        function_code: int = 3,
        register_address: int = 0,
        register_value: float = 0.0,
        raw_payload: bytes = b"",
        timestamp: Optional[float] = None
    ):
        """
        Constructor pentru instantierea unui pachet Modbus TCP.

        Args:
            src_ip (str): Adresa IP sursa a pachetului (ex: 192.168.1.10).
            dst_ip (str): Adresa IP destinatie (ex: 192.168.1.50).
            src_port (int): Portul TCP sursa.
            dst_port (int): Portul TCP destinatie (standard 502).
            transaction_id (int): ID tranzactie MBAP.
            protocol_id (int): ID protocol MBAP (0 = Modbus TCP).
            length (int): Campul lungime din antetul MBAP.
            unit_id (int): ID unitate / adresa sclav Modbus (1-247).
            function_code (int): Codul de functie industrial (1-127).
            register_address (int): Adresa de start a registrului sau bobinei.
            register_value (float): Valoarea scrisa sau numarul de elemente cerute.
            raw_payload (bytes): Continutul binar brut al pachetului.
            timestamp (float, optional): Momentul receptionarii pachetului (secunde).
        """
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.transaction_id = transaction_id
        self.protocol_id = protocol_id
        self.length = length
        self.unit_id = unit_id
        self.function_code = function_code
        self.register_address = register_address
        self.register_value = register_value
        self.raw_payload = raw_payload
        self.timestamp = timestamp if timestamp is not None else time.time()

    @property
    def is_write_operation(self) -> bool:
        """
        Verifica daca pachetul contine o comanda industriala de scriere / comanda proces.

        Returns:
            bool: True daca este FC05, FC06, FC15, FC16 etc., False pentru citiri.
        """
        return self.function_code in WRITE_FUNCTION_CODES

    @property
    def is_read_operation(self) -> bool:
        """
        Verifica daca pachetul contine o comanda industriala pasiva de citire / telemetrie.

        Returns:
            bool: True daca este FC01, FC02, FC03, FC04, False altfel.
        """
        return self.function_code in READ_FUNCTION_CODES

    def get_function_name(self) -> str:
        """
        Returneaza denumirea standardizata a codului de functie Modbus.

        Returns:
            str: Ex: 'Read Holding Registers (FC03)' sau 'Unknown Function (FC99)'
        """
        return MODBUS_FUNCTION_NAMES.get(self.function_code, f"Unknown Function (FC{self.function_code})")

    def to_bytes(self) -> bytes:
        """
        Serializeaza pachetul intr-un flux de octeti Modbus TCP conform specificatiei.

        Returns:
            bytes: Cadrul binar Modbus TCP (MBAP Header + PDU).
        """
        # Daca avem deja raw_payload si e valid, il putem returna
        if self.raw_payload and len(self.raw_payload) >= 8:
            return self.raw_payload

        # MBAP Header format: >HHHB (Transaction ID, Protocol ID, Length, Unit ID)
        # Lungimea PDU = 1 octet (Function Code) + 4 octeti (Adresa + Valoare/Cantitate) = 5
        # Lungimea MBAP = unit_id (1) + pdu (5) = 6
        pdu_length = 6
        mbap = struct.pack(">HHHB", self.transaction_id, self.protocol_id, pdu_length, self.unit_id)

        # Tratam valoarea ca intreg pe 16 biti pentru serializare
        val_int = int(self.register_value) & 0xFFFF
        addr_int = int(self.register_address) & 0xFFFF
        pdu = struct.pack(">BHH", self.function_code, addr_int, val_int)

        return mbap + pdu

    @classmethod
    def from_bytes(
        cls,
        raw_bytes: bytes,
        src_ip: str = "127.0.0.1",
        dst_ip: str = "127.0.0.1",
        src_port: int = 50000,
        dst_port: int = 502,
        timestamp: Optional[float] = None
    ) -> "ModbusPacket":
        """
        Decodifica un cadru binar Modbus TCP primit prin socket sau extras din PCAP.

        Args:
            raw_bytes (bytes): Cadrul brut de octeti.
            src_ip (str): IP-ul sursa de la nivelul retea.
            dst_ip (str): IP-ul destinatie.
            src_port (int): Portul sursa.
            dst_port (int): Portul destinatie.
            timestamp (float, optional): Timpul receptionarii.

        Returns:
            ModbusPacket: Obiectul decodificat si structurat.
        """
        if len(raw_bytes) < 7:
            # Pachet trunchiat sau incomplet
            return cls(
                src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                raw_payload=raw_bytes, timestamp=timestamp
            )

        # Decodificare MBAP Header (7 octeti: TransID, ProtoID, Length, UnitID)
        trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", raw_bytes[:7])

        function_code = 0
        register_address = 0
        register_value = 0.0

        if len(raw_bytes) >= 8:
            function_code = raw_bytes[7]

        if len(raw_bytes) >= 12:
            # PDU standard pentru cereri uzuale (FC01-06) contine adresa (2 octeti) si valoare/numar (2 octeti)
            register_address, raw_val = struct.unpack(">HH", raw_bytes[8:12])
            register_value = float(raw_val)

        return cls(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transaction_id=trans_id,
            protocol_id=proto_id,
            length=length,
            unit_id=unit_id,
            function_code=function_code,
            register_address=register_address,
            register_value=register_value,
            raw_payload=raw_bytes,
            timestamp=timestamp
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Transforma atributele pachetului intr-un dictionar usor de inspectat si serializat JSON.

        Returns:
            Dict[str, Any]: Atributele detaliate ale pachetului.
        """
        return {
            "timestamp": round(self.timestamp, 4),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "transaction_id": self.transaction_id,
            "protocol_id": self.protocol_id,
            "length": self.length,
            "unit_id": self.unit_id,
            "function_code": self.function_code,
            "function_name": self.get_function_name(),
            "register_address": self.register_address,
            "register_value": self.register_value,
            "is_write": self.is_write_operation,
            "is_read": self.is_read_operation
        }

    def __repr__(self) -> str:
        """
        Reprezentare lizibila sub forma de sir de caractere.
        """
        op = "WRITE" if self.is_write_operation else ("READ" if self.is_read_operation else "OTHER")
        return (
            f"<ModbusPacket [{op}] {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} | "
            f"FC={self.function_code} Addr={self.register_address} Val={self.register_value}>"
        )
