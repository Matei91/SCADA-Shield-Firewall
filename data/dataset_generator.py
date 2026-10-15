"""
=============================================================================
MODUL: data/dataset_generator.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Acest modul implementeaza un generator si incarcator de date pentru traficul
    industrial Modbus TCP, modelat fidel dupa specificatia benchmark-ului academic:
    Mississippi State University (MSU) SCADA Lab Gas Pipeline Dataset (Tommy Morris et al.).

    Setul de date contine atat trafic normal de monitorizare (poling HMI periodic,
    interogari de registre senzori, comenzi autorizate de mentenanta), cat si
    vectori reprezentativi de atac specifici retelelor operationale (OT/ICS):
      - Atacuri de tip 'Unauthorized Write' (injectare comenzi de scriere din surse neautorizate)
      - Atacuri de tip 'Physical Limits Tampering' (supracomanda a parametrilor de presiune/temperatura)
      - Atacuri de tip 'Reconnaissance / Modbus Scan' (baleierea ID-urilor de slave si a hartilor de registre)
      - Atacuri de tip 'Denial of Service (DoS Burst / Flood)' (inundare port 502)
      - Atacuri cu pachete malformate (violari ale specificatiei MBAP - Protocol ID invalid, lungimi false)
      - Anomalii subtile de timing / deviatie comportamentala (tintite pentru detectorul AI)
=============================================================================
"""

import os
import random
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple


def get_default_dataset_path() -> str:
    """
    Returneaza calea absoluta implicita catre fisierul CSV cu datele industriale.

    Returns:
        str: Calea catre fisierul ics_modbus_dataset.csv
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "ics_modbus_dataset.csv")


def generate_scada_modbus_dataset(num_packets: int = 12000, random_seed: int = 42) -> pd.DataFrame:
    """
    Genereaza un set de date sintetic, dar extrem de realist, reprezentand traficul
    Modbus TCP dintr-o statie industriala SCADA de distributie si transport gaz.

    Distributia pachetelor:
      - ~78% Trafic normal (poling ciclic HMI, actualizari senzori, scrieri autorizate ocazionale)
      - ~22% Trafic de atac (impartit pe 6 scenarii distincte de amenintari industriale)

    Args:
        num_packets (int): Numarul total de pachete de generat. Implicit 12000.
        random_seed (int): Samanta de randomizare pentru reproductibilitate stiintifica.

    Returns:
        pd.DataFrame: DataFrame pandas continand caracteristicile de retea si etichetele.
    """
    random.seed(random_seed)
    np.random.seed(random_seed)

    records: List[Dict] = []
    current_time = 1700000000.0  # Timestamp initial de referinta (secunde)

    # Entitati de retea conform arhitecturii standard Purdue Model (Nivelul 2 & 1)
    PLC_IP = "192.168.1.50"         # Controler industrial (Slave/Server Modbus)
    HMI_IP = "192.168.1.10"         # Statie HMI operator (Master legitim)
    ENG_IP = "192.168.1.20"         # Statie inginerie de proces (Master legitim)
    HISTORIAN_IP = "192.168.1.30"   # Server de arhivare date telemetrie (Legitim)
    ATTACKER_IP_1 = "192.168.1.99"  # Laptop compromis conectat in LAN-ul industrial
    ATTACKER_IP_2 = "10.0.0.5"      # Atacator extern routat prin VPN/IT compromis

    # Registre senzoriale (citire) si de control (scriere)
    READ_REGISTERS = [1000, 1001, 1002]  # Presiune, Debit, Temperatura
    SETPOINT_REGISTERS = [1010, 1011]    # Setpoint Presiune (20-80), Setpoint Pompa (500-3000)
    CRITICAL_COILS = [2001, 2002]        # Valva Oprire Urgenta, Valva Suprapresiune

    # Dictionar pentru urmarirea frecventei pe IP (necesar calculului inter-arrival time)
    last_packet_time: Dict[str, float] = {}

    # Generam pachetele secvential in timp
    tx_id_counter = 1

    for i in range(num_packets):
        # Determinam daca pachetul curent este normal sau atac (80% / 20%)
        is_attack = random.random() < 0.22

        if not is_attack:
            # -----------------------------------------------------------------
            # SCENARIUL 1: TRAFIC INDUSTRIAL NORMAL (REGIM REGULAT)
            # -----------------------------------------------------------------
            label = "NORMAL"
            attack_type = "NORMAL"

            # Majoritatea interogarilor vin de la HMI (85%), Historian (12%) sau Eng Station (3%)
            r_sender = random.random()
            if r_sender < 0.85:
                src_ip = HMI_IP
                # HMI citeste registrele de telemetrie sau bobinele
                function_code = random.choice([1, 2, 3, 4])
                if function_code in [1, 2]:
                    reg_addr = random.choice(CRITICAL_COILS)
                    reg_val = random.choice([1, 2, 4])  # Numar de bobine citite
                else:
                    reg_addr = random.choice(READ_REGISTERS + SETPOINT_REGISTERS)
                    reg_val = random.choice([1, 2, 4])  # Numar de registre citite
                dt = random.uniform(0.18, 0.45)  # Interval ciclic de poling HMI
            elif r_sender < 0.97:
                src_ip = HISTORIAN_IP
                function_code = random.choice([3, 4])  # Doar citire telemetrie
                reg_addr = random.choice(READ_REGISTERS)
                reg_val = random.randint(1, 3)
                dt = random.uniform(0.8, 2.5)  # Poling mai rar al bazei de date de istoric
            else:
                # Comanda legitima de reglare proces transmisa de statia de inginerie
                src_ip = ENG_IP
                function_code = 6  # Write Single Register
                reg_addr = random.choice(SETPOINT_REGISTERS)
                if reg_addr == 1010:
                    reg_val = round(random.uniform(35.0, 65.0), 1)  # Presiune sigura
                else:
                    reg_val = round(random.uniform(1000.0, 2200.0), 1)  # RPM sigur
                dt = random.uniform(2.0, 8.0)

            dst_ip = PLC_IP
            src_port = random.randint(49152, 65535)
            dst_port = 502  # Portul standard Modbus TCP
            protocol_id = 0  # 0 indica Modbus TCP conform specificatiei
            unit_id = 1      # Unitatea / Adresa slave
            length = 6       # Lungimea standard a PDU-ului de cerere Modbus

        else:
            # -----------------------------------------------------------------
            # SCENARIUL 2: GENERARE ATACURI SPECIFICE RETELELOR INDUSTRIALE
            # -----------------------------------------------------------------
            label = "ATTACK"
            attack_variant = random.choice([
                "UNAUTHORIZED_WRITE",
                "CRITICAL_TAMPERING",
                "RECON_SCAN",
                "DOS_BURST",
                "MALFORMED_PACKET",
                "ANOMALOUS_DRIFT"
            ])
            attack_type = attack_variant

            if attack_variant == "UNAUTHORIZED_WRITE":
                # Atacator neautorizat incearca sa scrie direct pe PLC
                src_ip = random.choice([ATTACKER_IP_1, ATTACKER_IP_2])
                dst_ip = PLC_IP
                src_port = random.randint(49152, 65535)
                dst_port = 502
                function_code = random.choice([5, 6, 15, 16])  # Forteaza comanda de scriere
                reg_addr = random.choice(CRITICAL_COILS + SETPOINT_REGISTERS)
                reg_val = 1 if reg_addr in CRITICAL_COILS else 999
                protocol_id = 0
                unit_id = 1
                length = 6
                dt = random.uniform(0.1, 1.2)

            elif attack_variant == "CRITICAL_TAMPERING":
                # Sabotaj fizic (Stuxnet style): Sursa poate folosi un IP mascat sau autorizat,
                # dar valoarea scrisa depaseste limitele de siguranta ale conductei de gaz!
                src_ip = random.choice([ENG_IP, ATTACKER_IP_1])
                dst_ip = PLC_IP
                src_port = random.randint(49152, 65535)
                dst_port = 502
                function_code = 6  # Write Single Register
                reg_addr = 1010    # Setpoint presiune
                reg_val = round(random.choice([150.0, 250.0, 500.0, 9999.0]), 1)  # Presiune catastrofala!
                protocol_id = 0
                unit_id = 1
                length = 6
                dt = random.uniform(0.3, 1.5)

            elif attack_variant == "RECON_SCAN":
                # Scanare de recunoastere industrial: atacatorul sondeaza toate ID-urile posibile
                # de slave (1..247) sau adrese de memorie aleatoare pentru a gasi topologia
                src_ip = ATTACKER_IP_1
                dst_ip = PLC_IP
                src_port = random.randint(49152, 65535)
                dst_port = 502
                function_code = random.choice([1, 3, 17, 43])  # Coduri normale + Report Slave ID
                unit_id = random.randint(1, 250)               # Inclusiv adrese invalide
                reg_addr = random.randint(1, 65000)            # Adrese fictive de memorie
                reg_val = random.randint(1, 100)
                protocol_id = 0
                length = 6
                dt = random.uniform(0.01, 0.05)  # Baleiere foarte rapida

            elif attack_variant == "DOS_BURST":
                # Atac de inundare pentru blocarea procesorului PLC-ului (Denial of Control)
                src_ip = ATTACKER_IP_1
                dst_ip = PLC_IP
                src_port = random.randint(49152, 65535)
                dst_port = 502
                function_code = random.choice([3, 16])
                unit_id = 1
                reg_addr = 1000
                reg_val = 1
                protocol_id = 0
                length = 6
                dt = random.uniform(0.001, 0.005)  # Rafale de sute de pachete/secunda

            elif attack_variant == "MALFORMED_PACKET":
                # Pachete cu violare de protocol pentru ocolirea firewall-urilor superficiale
                src_ip = random.choice([ATTACKER_IP_1, ATTACKER_IP_2])
                dst_ip = PLC_IP
                src_port = random.randint(49152, 65535)
                dst_port = 502
                function_code = random.choice([0, 99, 128, 255])  # Coduri de functie ilegale
                unit_id = random.choice([0, 250, 255])
                reg_addr = 9999
                reg_val = 0
                protocol_id = random.choice([1, 255, 65535])      # Diferit de 0 (ilegal in Modbus TCP)
                length = random.choice([0, 1, 2048])              # Lungime MBAP inconsistenta
                dt = random.uniform(0.05, 0.5)

            else:  # ANOMALOUS_DRIFT
                # Pachet valid din punct de vedere sintactic, dar cu anomalii de succesiune si frecventa
                # creat special pentru a testa capabilitatea de detectie bazata pe AI / Machine Learning
                src_ip = random.choice([HMI_IP, ENG_IP, ATTACKER_IP_1])
                dst_ip = PLC_IP
                src_port = random.randint(49152, 65535)
                dst_port = 502
                function_code = 3
                unit_id = 1
                reg_addr = random.choice(READ_REGISTERS)
                reg_val = 100  # Numar neobisnuit de mare de registre cerute
                protocol_id = 0
                length = 6
                dt = random.uniform(0.005, 0.02)  # Rata neobisnuita pentru o statie legitima

        # Calculam timestamp-ul curent si timpul de sosire inter-pachete
        current_time += dt
        inter_arrival_time = current_time - last_packet_time.get(src_ip, current_time - dt)
        last_packet_time[src_ip] = current_time

        # Calculam caracteristicile derivate (features) pentru modelul de Machine Learning
        is_write_op = 1 if function_code in [5, 6, 15, 16, 22, 23] else 0
        is_known_ip = 1 if src_ip in [HMI_IP, ENG_IP, HISTORIAN_IP] else 0
        is_critical_reg = 1 if (reg_addr in CRITICAL_COILS or reg_addr in SETPOINT_REGISTERS) else 0

        # Estimam rata de pachete aproximativa (packets per second)
        packet_rate = round(1.0 / max(inter_arrival_time, 0.0001), 2)

        record = {
            "timestamp": round(current_time, 4),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "transaction_id": tx_id_counter,
            "protocol_id": protocol_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": function_code,
            "register_address": reg_addr,
            "register_value": reg_val,
            "inter_arrival_time": round(inter_arrival_time, 4),
            "packet_rate": packet_rate,
            "is_write_op": is_write_op,
            "is_known_ip": is_known_ip,
            "is_critical_reg": is_critical_reg,
            "attack_type": attack_type,
            "label": label
        }

        records.append(record)
        tx_id_counter = (tx_id_counter + 1) % 65535

    df = pd.DataFrame(records)
    return df


def save_dataset_to_csv(df: pd.DataFrame, output_path: str = None) -> str:
    """
    Salveaza setul de date generat intr-un fisier CSV pe disc.

    Args:
        df (pd.DataFrame): DataFrame-ul continand traficul SCADA.
        output_path (str, optional): Calea de salvare. Daca este None, foloseste get_default_dataset_path().

    Returns:
        str: Calea absoluta a fisierului salvat.
    """
    if output_path is None:
        output_path = get_default_dataset_path()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    return output_path


def load_scada_dataset(filepath: str = None) -> pd.DataFrame:
    """
    Incarca setul de date SCADA Modbus de pe disc. Daca fisierul nu exista,
    il genereaza automat si il salveaza pe disc.

    Args:
        filepath (str, optional): Calea catre fisierul CSV.

    Returns:
        pd.DataFrame: Setul de date incarcat si validat.
    """
    if filepath is None:
        filepath = get_default_dataset_path()

    if not os.path.exists(filepath):
        df = generate_scada_modbus_dataset(num_packets=12000)
        save_dataset_to_csv(df, filepath)
    else:
        df = pd.read_csv(filepath)

    return df


if __name__ == "__main__":
    print("[*] Generare set de date industrial Modbus (MSU SCADA Gas Pipeline)...")
    dataset = generate_scada_modbus_dataset(num_packets=12000)
    saved_path = save_dataset_to_csv(dataset)
    print(f"[+] Set de date salvat cu succes la: {saved_path}")
    print(f"[+] Total pachete: {len(dataset)}")
    print(f"[+] Distributie clase:\n{dataset['label'].value_counts()}")
    print(f"[+] Distributie tipuri atac:\n{dataset['attack_type'].value_counts()}")
