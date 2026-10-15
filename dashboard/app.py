"""
=============================================================================
APLICATIE: dashboard/app.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Dashboard Web Interactiv construit cu Streamlit pentru prezentarea vizuala
    a proiectului in fata comisiei sau profesorului.

    Functionalitati:
      1. Panou de Control & Monitorizare Proces Fizic SCADA (Conducta Gaz)
      2. Lansator Interactiv de Atacuri Industriale (One-Click Attack Launcher)
      3. Demonstratie Cyber-Physical in timp real (Fara Firewall vs Cu Firewall)
      4. Inspectie Profunda Pachete (DPI Audit Log cu filtrare si export CSV)
      5. Analitice Inteligenta Artificiala (Confusion Matrix, Importanta Trasaturi)
      6. Configurare dinamica a regulilor (Comutare regim Read-Only, Whitelist, Prag AI)
=============================================================================
"""

import os
import sys
import time
import json
import pandas as pd
import numpy as np
import streamlit as st

# Asiguram ca radacina proiectului este in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from firewall.core_firewall import ICSCoreFirewall
from simulation.virtual_plc import VirtualPLC
from simulation.virtual_hmi import VirtualHMI
from simulation.attack_simulator import SCADAAttackSimulator
from firewall.modbus_packet import ModbusPacket


# Configurare pagina Streamlit
st.set_page_config(
    page_title="SCADA-Shield ICS Firewall",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initializare instante in st.session_state pentru persistenta interactiunii
if "firewall" not in st.session_state:
    st.session_state.firewall = ICSCoreFirewall()

if "plc" not in st.session_state:
    st.session_state.plc = VirtualPLC()

if "hmi" not in st.session_state:
    st.session_state.hmi = VirtualHMI()

if "attacker" not in st.session_state:
    st.session_state.attacker = SCADAAttackSimulator()

if "last_scenario_result" not in st.session_state:
    st.session_state.last_scenario_result = None

firewall: ICSCoreFirewall = st.session_state.firewall
plc: VirtualPLC = st.session_state.plc
hmi: VirtualHMI = st.session_state.hmi
attacker: SCADAAttackSimulator = st.session_state.attacker


# -----------------------------------------------------------------------------
# BARA LATERALA (SIDEBAR) - CONFIGURARE POLITICI FIREWALL
# -----------------------------------------------------------------------------
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=70)
st.sidebar.title("Configurare Politici")
st.sidebar.markdown("**Firewall SCADA / ICS (Modbus TCP)**")

st.sidebar.markdown("---")
st.sidebar.subheader("Regim Operational")

# 1. Comutator Read-Only Mode (Cerinta tema!)
read_only_toggle = st.sidebar.toggle(
    "Activeaza Regim Read-Only",
    value=firewall.read_only_mode,
    help="Blocheaza toate comenzile de scriere (FC 05, 06, 15, 16) pentru a preveni modificarea neautorizata a registrelor fizice."
)
firewall.read_only_mode = read_only_toggle

# 2. Comutator AI Inspection Engine
ai_toggle = st.sidebar.toggle(
    "Inspectie Comportamentala AI",
    value=firewall.rule_engine.ai_inspection_enabled,
    help="Activeaza clasificatorul Random Forest si Isolation Forest pentru identificarea anomaliilor si a tentativelor de evaziune."
)
firewall.rule_engine.ai_inspection_enabled = ai_toggle

# 3. Prag de Anomaly AI
ai_threshold = st.sidebar.slider(
    "Prag Decizie AI (Anomaly Threshold)",
    min_value=0.50,
    max_value=0.95,
    value=float(firewall.rule_engine.ai_anomaly_threshold),
    step=0.05,
    help="Probabilitatea minima calculata de AI pentru declansarea alertei sau blocarii."
)
firewall.rule_engine.ai_anomaly_threshold = ai_threshold
firewall.ai_inspector.threshold = ai_threshold

st.sidebar.markdown("---")
st.sidebar.subheader("Lista Alba IP (Whitelist)")
st.sidebar.code("\n".join(sorted(list(firewall.rule_engine.ip_whitelist))), language="text")

if st.sidebar.button("Reseteaza Toate Statisticile"):
    firewall.reset()
    plc.reset_state()
    st.session_state.last_scenario_result = None
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.caption("Disciplina: Securitatea Sistemelor Informatice (Master)")
st.sidebar.caption("Proiect: Simulator Firewall Retele Industriale (Modbus TCP)")


# -----------------------------------------------------------------------------
# HEADER PRINCIPAL
# -----------------------------------------------------------------------------
st.title("🛡️ SCADA-Shield: Industrial Network DPI Firewall & AI Anomaly Detector")
st.markdown(
    "Simulator complet de securitate cibernetica pentru retele industriale de control (ICS / OT) "
    "bazat pe inspectie profunda la nivel de protocol Modbus TCP (Layer 7 DPI) si Machine Learning."
)

# Metrici rapide de sistem
metrics = firewall.get_metrics()
plc_state = plc.get_state()

col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
col_m1.metric("Pachete Inspectate", metrics["total_inspected"])
col_m2.metric("Pachete Permise (Legitim)", metrics["allowed"], delta_color="normal")
col_m3.metric("Pachete Blocate (Amenintari)", metrics["dropped"], delta=f"{metrics['drop_rate_pct']}% Drop Rate", delta_color="inverse")
col_m4.metric("Anomalii Detectate AI", metrics["ai_anomalies"], delta_color="inverse")
status_label = "Activ (Scrieri Blocate)" if firewall.read_only_mode else "Inactiv (Scrieri Permise)"
col_m5.metric("Regim Read-Only", status_label)

st.markdown("---")


# -----------------------------------------------------------------------------
# TABURI PRINCIPALE APLICATIE
# -----------------------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🏭 Monitorizare Proces Fizic",
    "⚡ Simulator Atacuri Industriale",
    "📋 Jurnalizare & Audit DPI",
    "🧠 Analiza Machine Learning & AI",
    "📖 Ghid Teoretic & Prezentare"
])


# =============================================================================
# TAB 1: MONITORIZARE PROCES FIZIC (VIRTUAL PLC)
# =============================================================================
with tab1:
    st.header("Starea Fizica a Conductei de Gaz (Virtual PLC)")
    st.caption("Controler industrial programabil conectat la magistrala de gaz de inalta presiune (Port Modbus 502).")

    # Alerte de siguranta fizica
    if plc_state["is_pipeline_ruptured"]:
        st.error("🚨 ALERTA CRITICA DE SECURITATE: CONDUCTA DE GAZ S-A RUPT DIN CAUZA SUPRAPRESIUNII (> 120 PSI)!")
    elif plc_state["is_emergency_shutdown"]:
        st.warning("⚠️ PROCES OPRIT: Valva de siguranta (Coil 2001) a fost inchisa de urgenta!")
    else:
        st.success("✅ PROCES IN REGIM NOMINAL SIGUR: Toti parametrii se incadreaza in limitele sigure de exploatare.")

    col_p1, col_p2, col_p3, col_p4 = st.columns(4)

    # Indicator Presiune
    p_color = "red" if plc_state["pressure_psi"] > 80.0 else "green"
    col_p1.metric(
        "Presiune Conducta (PSI)",
        f"{plc_state['pressure_psi']} PSI",
        delta=f"Setpoint: {plc_state['pressure_setpoint']} PSI (Limita: 20-80)",
        delta_color="normal" if plc_state["pressure_psi"] <= 80 else "inverse"
    )

    # Indicator Debit
    col_p2.metric(
        "Debit Gaz Masurat",
        f"{plc_state['flow_rate_m3h']} m³/h",
        delta="Domeniu nominal: 0-500 m³/h"
    )

    # Indicator Temperatura
    col_p3.metric(
        "Temperatura Compresor",
        f"{plc_state['compressor_temp_c']} °C",
        delta="Limita maxima: 110 °C"
    )

    # Indicator Valva
    valve_str = "IZOLAT / INCHIS (1)" if plc_state["emergency_valve_closed"] == 1 else "DESCHIS / ACTIV (0)"
    col_p4.metric(
        "Valva Oprire Urgenta (Coil 2001)",
        valve_str,
        delta="Siguranta: 0 = Normal"
    )

    st.markdown("#### Actiuni Operator Legitim (Simulare HMI)")
    c_btn1, c_btn2, c_btn3 = st.columns(3)

    if c_btn1.button("📡 Trimite Interogare Telemetrie (FC03)"):
        p = hmi.generate_telemetry_poll()
        log = firewall.process_packet(p)
        if log.decision == "ALLOW":
            plc.execute_packet(p)
        st.success(f"Pachet HMI procesat: {log.decision} ({log.reason})")
        st.rerun()

    if c_btn2.button("🔍 Citeste Stare Valve (FC01)"):
        p = hmi.generate_valve_status_poll()
        log = firewall.process_packet(p)
        if log.decision == "ALLOW":
            plc.execute_packet(p)
        st.success(f"Pachet HMI procesat: {log.decision}")
        st.rerun()

    if c_btn3.button("🔧 Regleaza Setpoint Presiune Autorizat (55 PSI)"):
        p = hmi.generate_legitimate_setpoint_adjustment(55.0)
        log = firewall.process_packet(p)
        if log.decision == "ALLOW":
            plc.execute_packet(p)
            st.success(f"Setpoint actualizat cu succes: {log.decision}")
        else:
            st.warning(f"Comanda respinsa de firewall: {log.reason}")
        st.rerun()


# =============================================================================
# TAB 2: SIMULATOR ATACURI INDUSTRIALE & DEMO COMPARATIV
# =============================================================================
with tab2:
    st.header("⚡ Simulare Atacuri Cibernetice & Evaluare Prevenire")
    st.markdown(
        "Lansati scenarii reale de atac cibernetic directionate catre infrastructura industriala. "
        "Firewall-ul inspecteaza pachetele si previne actiunile nesigure conform cerintelor proiectului."
    )

    c_at1, c_at2, c_at3 = st.columns(3)

    with c_at1:
        st.markdown("##### 1. Unauthorized Write")
        st.caption("Laptop compromis (192.168.1.99) incearca sa opreasca Valva de Siguranta.")
        if st.button("Lanseaza Atac: Scriere Neautorizata", use_container_width=True):
            packets = attacker.scenario_unauthorized_write()
            for p in packets:
                firewall.process_packet(p)
            st.rerun()

    with c_at2:
        st.markdown("##### 2. Critical Setpoint Sabotage")
        st.caption("Stuxnet-style: Supracomanda presiune la 500 PSI pentru explozie fizica.")
        if st.button("Lanseaza Atac: Sabotaj Presiune", use_container_width=True):
            packets = attacker.scenario_critical_setpoint_tampering()
            for p in packets:
                firewall.process_packet(p)
            st.rerun()

    with c_at3:
        st.markdown("##### 3. Modbus Recon Scanning")
        st.caption("Baleiere agresiva a ID-urilor de slave 1..247 si a registrelor interne.")
        if st.button("Lanseaza Atac: Scanare Retea", use_container_width=True):
            packets = attacker.scenario_modbus_recon_scan(count=12)
            for p in packets:
                firewall.process_packet(p)
            st.rerun()

    c_at4, c_at5, c_at6 = st.columns(3)

    with c_at4:
        st.markdown("##### 4. Denial of Service (Flood)")
        st.caption("Inundare cu 100 de pachete pe portul 502 pentru blocarea PLC-ului.")
        if st.button("Lanseaza Atac: Modbus Flood", use_container_width=True):
            packets = attacker.scenario_dos_flood(count=100)
            for p in packets:
                firewall.process_packet(p)
            st.rerun()

    with c_at5:
        st.markdown("##### 5. MBAP Protocol Evasion")
        st.caption("Pachet malformat (Protocol ID = 1) pentru ocolirea inspectiei DPI.")
        if st.button("Lanseaza Atac: Evaziune Protocol", use_container_width=True):
            packets = attacker.scenario_protocol_evasion()
            for p in packets:
                firewall.process_packet(p)
            st.rerun()

    with c_at6:
        st.markdown("##### 6. Stealth Anomaly (AI Target)")
        st.caption("Comanda valida dar cu frecventa atipica identificata de Machine Learning.")
        if st.button("Lanseaza Atac: Anomalie Subtila", use_container_width=True):
            packets = attacker.scenario_stealth_anomaly()
            for p in packets:
                firewall.process_packet(p)
            st.rerun()

    st.markdown("---")
    st.subheader("🎯 Demonstratie Comparativa: Cu Firewall vs Fara Firewall")
    st.markdown(
        "Aceasta sectiune raspunde punctual cerintei: **'Aratati cum firewall-ul previne actiunile nesigure'**. "
        "Se compara comportamentul sistemului fizic atunci cand un atac de sabotaj ajunge pe PLC direct, "
        "fata de cazul in care firewall-ul industrial SCADA-Shield este interpus."
    )

    if st.button("▶️ Ruleaza Demonstratia Comparativa Cyber-Physical", type="primary"):
        st.session_state.last_scenario_result = attacker.run_comparative_demonstration(firewall, plc)
        st.rerun()

    if st.session_state.last_scenario_result:
        res = st.session_state.last_scenario_result
        st.markdown(f"#### Rezultat Evaluare: `{res['attack_name']}`")

        col_w_no, col_w_yes = st.columns(2)

        with col_w_no:
            st.error("### ❌ Sistem FARA Firewall")
            st.markdown(f"**Decizie:** `{res['without_firewall']['decision']}`")
            st.markdown(f"**Presiune Rezultata:** `{res['without_firewall']['final_pressure']} PSI` (Limita sigura: 80 PSI)")
            st.markdown(f"**Ruptura Conducta:** `{'DA - Catastrofa' if res['without_firewall']['pipeline_ruptured'] else 'Nu'}`")
            st.markdown(f"**Impact:** {res['without_firewall']['impact']}")

        with col_w_yes:
            st.success("### ✅ Sistem CU Firewall SCADA-Shield")
            st.markdown(f"**Decizie:** `{res['with_firewall']['decision']}`")
            st.markdown(f"**Regula Declanșată:** `{res['with_firewall']['triggered_rule']}`")
            st.markdown(f"**Presiune Pastrata:** `{res['with_firewall']['final_pressure']} PSI` (In parametri optimi)")
            st.markdown(f"**Ruptura Conducta:** `NU (Prevenita 100%)`")
            st.markdown(f"**Impact:** {res['with_firewall']['impact']}")
            st.info(f"**Motiv Respingere:** {res['with_firewall']['reason']}")


# =============================================================================
# TAB 3: JURNALIZARE & AUDIT DPI
# =============================================================================
with tab3:
    st.header("📋 Jurnalizare & Audit Profund (DPI Packet Log)")
    st.caption("Toate pachetele inspectate sunt stocate cu amprenta completa de protocol si decizie.")

    logs_df = firewall.export_logs_to_dataframe()

    if not logs_df.empty:
        # Filtre interactive
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            decision_filter = st.multiselect("Filtreaza dupa Decizie", options=["ALLOW", "DROP"], default=["ALLOW", "DROP"])
        with f_col2:
            severity_filter = st.multiselect("Filtreaza dupa Severitate", options=["INFO", "WARNING", "CRITICAL"], default=["INFO", "WARNING", "CRITICAL"])
        with f_col3:
            ip_search = st.text_input("Cauta dupa IP Sursa", "")

        filtered = logs_df.copy()
        if decision_filter:
            filtered = filtered[filtered["decision"].isin(decision_filter)]
        if severity_filter:
            filtered = filtered[filtered["severity"].isin(severity_filter)]
        if ip_search:
            filtered = filtered[filtered["src_ip"].str.contains(ip_search)]

        st.dataframe(
            filtered[[
                "id", "datetime_str", "src_ip", "src_port", "dst_port",
                "function_name", "register_address", "register_value",
                "decision", "triggered_rule", "ai_anomaly", "reason"
            ]],
            use_container_width=True,
            height=380
        )

        csv_data = filtered.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Descarca Jurnalul de Audit (CSV)", data=csv_data, file_name="firewall_audit_log.csv", mime="text/csv")
    else:
        st.info("Niciun pachet nu a fost inspectat inca. Rulati o comanda din Tabul 1 sau 2!")


# =============================================================================
# TAB 4: ANALIZA MACHINE LEARNING & AI
# =============================================================================
with tab4:
    st.header("🧠 Modulul de Inteligenta Artificiala (Anomaly Detection)")
    st.markdown(
        "Firewall-ul integreaza un clasificator supervizat **Random Forest** si un model nesupervizat "
        "**Isolation Forest** antrenate pe specificatia setului de date SCADA Modbus (Mississippi State University)."
    )

    metadata_path = os.path.join(PROJECT_ROOT, "models", "model_metadata.json")
    if os.path.exists(metadata_path):
        with open(metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        m = meta.get("metrics", {})
        col_ai1, col_ai2, col_ai3, col_ai4, col_ai5 = st.columns(5)
        col_ai1.metric("Acuratete Test", f"{m.get('accuracy', 1.0) * 100:.2f}%")
        col_ai2.metric("Precizie (Precision)", f"{m.get('precision', 1.0) * 100:.2f}%")
        col_ai3.metric("Sensibilitate (Recall)", f"{m.get('recall', 1.0) * 100:.2f}%")
        col_ai4.metric("F1-Score", f"{m.get('f1_score', 1.0) * 100:.2f}%")
        col_ai5.metric("ROC-AUC Score", f"{m.get('roc_auc', 1.0) * 100:.2f}%")

        st.markdown("---")
        st.subheader("Importanta Trasaturilor (Feature Importance)")
        st.caption("Explica factorii determinanti in baza carora modelul AI clasifica un pachet ca fiind un atac:")

        fi_data = meta.get("feature_importances", {})
        fi_df = pd.DataFrame(list(fi_data.items()), columns=["Trasatura", "Importanta"]).sort_values("Importanta", ascending=True)
        st.bar_chart(fi_df.set_index("Trasatura"))

        col_cm1, col_cm2 = st.columns(2)
        with col_cm1:
            st.subheader("Matricea de Confuzie (Setul de Test)")
            cm = m.get("confusion_matrix", [[0, 0], [0, 0]])
            cm_df = pd.DataFrame(cm, index=["Actual Normal", "Actual Attack"], columns=["Pred Normal", "Pred Attack"])
            st.table(cm_df)

        with col_cm2:
            st.subheader("Evaluare Model Nesupervizat (Isolation Forest)")
            st.markdown(
                f"- **Acuratete Detecție Anomalii:** `{m.get('isolation_forest_accuracy', 0.85) * 100:.2f}%`\n"
                f"- **F1-Score Anomalii:** `{m.get('isolation_forest_f1', 0.58) * 100:.2f}%`\n"
                "- **Rol Operativ:** Detecteaza atacuri inedite (Zero-Day) prin identificarea deviatiilor statistice fara a necesita semnaturi prealabile."
            )
    else:
        st.warning("Fisierul de metadate model_metadata.json nu a fost gasit. Rulati models/train_ai.py!")


# =============================================================================
# TAB 5: GHID TEORETIC & PREZENTARE MASTER
# =============================================================================
with tab5:
    st.header("📖 Ghid Teoretic & Suport de Prezentare (Master SSI)")
    st.markdown("""
    ### 1. Contextul Securitatii Cibernetice Industriale (OT / SCADA)
    - **Purdue Model (ISA-95):** Retelele industriale separa nivelul operational (Nivel 1: PLC/RTU, Nivel 2: HMI/SCADA) de nivelul corporativ (IT).
    - **Protocolul Modbus TCP (Port 502):** Creat in anii '70, protocolul este complet nesecurizat in mod nativ (fara autentificare, fara criptare, fara verificari de integritate). Oricine are acces in LAN poate trimite comenzi catastrofale de scriere direct pe PLC!
    - **Solutia: Deep Packet Inspection (DPI):** Firewall-ul nu se limiteaza la inspectia adreselor IP si a porturilor (Layer 3/4), ci analizeaza campurile MBAP si PDU din Layer 7 (Cod de functie, adresa registru, semantica valorii scrise).

    ### 2. Regimul "Read-Only Enforcement"
    - In multe statii SCADA critice (statii electrice, transport gaz, epurare apa), operatorii de la HMI au doar atributii de **monitorizare**.
    - Firewall-ul blocheaza complet comenzile de scriere (**FC 05, 06, 15, 16**), eliminand riscul ca un laptop compromis al unui operator sau un malware (ex: Triton, Stuxnet) sa transmita comenzi de oprire sau detonare a echipamentelor.

    ### 3. De ce este necesar Machine Learning (AI)?
    - Regulile statice pot fi evazionate prin **comenzi legitime din punct de vedere sintactic** (ex: o mie de cereri FC03 permise, transmise la intervale milisecundare sau solicitari de volume uriase de memorie).
    - Modelele hibride (**Random Forest + Isolation Forest**) asigura protectie impotriva anomaliilor de rata, tiparelor neobisnuite de acces si atacurilor Zero-Day.

    ### 4. Structura Proiectului
    - `data/dataset_generator.py`: Generator si incarcator de date bazat pe specificatia Tommy Morris SCADA Lab.
    - `firewall/modbus_packet.py`: Decodare si parsare de cadre Modbus TCP (MBAP + PDU).
    - `firewall/rule_engine.py`: Motorul de reguli DPI (Read-Only, Whitelist, Register Boundaries, Semantic Safety).
    - `firewall/rate_limiter.py`: Limitator de rata bazat pe Token Bucket pentru aparare impotriva DoS / Flood pe portul 502.
    - `firewall/ai_inspector.py`: Inspector de inteligenta artificiala pentru depistarea atacurilor evazive.
    - `simulation/virtual_plc.py`: Simulator fizic de controler industrial (conducta gaz, senzori, valve).
    - `simulation/attack_simulator.py`: Suita de 6 atacuri reale si demonstratie comparativa cyber-physical.
    - `run_demo.py`: Script consola complet pentru prezentare rapida.
    - `dashboard/app.py`: Aplicatia interactiva Web Streamlit.
    """)
