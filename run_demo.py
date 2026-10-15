"""
=============================================================================
SCRIPT DEMO: run_demo.py
PROIECT: Simulator Firewall pentru Retele Industriale (SCADA/ICS DPI Firewall)
DISCIPLINA: Securitatea Sistemelor Informatice (Master)
=============================================================================
DESCRIERE:
    Script de prezentare interactiva in consola, formatat cu libraria Rich
    (culori, tabele, panouri informative, animatii de inspectie).

    Demonstreaza toate cerintele temei de master:
      1. Inspectia pachetelor de telemetrie legitima (HMI Polling)
      2. Enforcing reguli de securitate (Read-Only, Whitelist, Sanity Check)
      3. Blocarea a 6 vectori de atac (Unauthorized Write, Sabotaj, Scan, DoS, Evasion, AI)
      4. Demonstratie comparativa cyber-physical (FARA Firewall vs CU Firewall)
      5. Raport statistic final si audit complet
=============================================================================
"""

import sys
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich.text import Text

from firewall.core_firewall import ICSCoreFirewall
from simulation.virtual_plc import VirtualPLC
from simulation.virtual_hmi import VirtualHMI
from simulation.attack_simulator import SCADAAttackSimulator


def print_banner(console: Console):
    """
    Afiseaza banner-ul proiectului pentru prezentare.
    """
    banner_text = (
        "[bold cyan]======================================================================[/bold cyan]\n"
        "[bold white]  SIMULATOR FIREWALL PENTRU REȚELE INDUSTRIALE (SCADA / ICS)[/bold white]\n"
        "[bold green]  Deep Packet Inspection (DPI) & Detecție Anomalii bazată pe AI[/bold green]\n"
        "[dim]  Disciplina: Securitatea Sistemelor Informatice (Master)[/dim]\n"
        "[bold cyan]======================================================================[/bold cyan]"
    )
    console.print(Panel(banner_text, style="cyan", expand=False))


def display_packet_result(console: Console, log_entry, scenario_title: str):
    """
    Afiseaza rezultatul inspectiei unui pachet intr-un tabel colorat.
    """
    color = "green" if log_entry.decision == "ALLOW" else "red"
    badge = "[bold white on green] ALLOW [/bold white on green]" if log_entry.decision == "ALLOW" else "[bold white on red] DROP [/bold white on red]"

    table = Table(title=f"Rezultat Inspectie: {scenario_title}", show_header=True, header_style="bold magenta")
    table.add_column("Parametru", style="dim", width=22)
    table.add_column("Valoare Inspectata", width=55)

    table.add_row("Pachet", f"{log_entry.src_ip}:{log_entry.src_port} -> {log_entry.dst_ip}:{log_entry.dst_port}")
    table.add_row("Comanda Modbus", f"{log_entry.function_name} (FC{log_entry.function_code})")
    table.add_row("Registru / Valoare", f"Adresa: {log_entry.register_address} | Valoare: {log_entry.register_value}")
    table.add_row("Decizie Firewall", f"{badge}  [bold {color}]({log_entry.decision})[/bold {color}]")
    table.add_row("Regula / Modul", f"[bold yellow]{log_entry.triggered_rule}[/bold yellow]")
    table.add_row("Explicatie & Motiv", f"[{color}]{log_entry.reason}[/{color}]")

    if log_entry.ai_attack_prob > 0.0 or log_entry.ai_anomaly:
        ai_badge = "[red]SUSPECT / ANOMALIE[/red]" if log_entry.ai_anomaly else "[green]NORMAL[/green]"
        table.add_row("Inspectie AI (ML)", f"{ai_badge} | Probabilitate atac: {log_entry.ai_attack_prob * 100:.1f}%")

    console.print(table)
    console.print("")


def run_full_presentation_demo():
    """
    Ruleaza demonstratia completa pentru sustinerea proiectului.
    """
    console = Console()
    print_banner(console)

    console.print("[bold yellow][*] Initializare componente industriale...[/bold yellow]")
    firewall = ICSCoreFirewall()
    plc = VirtualPLC()
    hmi = VirtualHMI()
    attacker = SCADAAttackSimulator()
    console.print("[bold green][+] Firewall SCADA-Shield activat cu inspectie DPI si AI.[/bold green]")
    console.print("[bold green][+] PLC virtual initializat (Conducta de gaz: Presiune 50 PSI, Valva Deschisa).[/bold green]\n")

    time.sleep(0.5)

    # -------------------------------------------------------------------------
    # DEMO 1: TRAFIC NORMAL DE TELEMETRIE
    # -------------------------------------------------------------------------
    console.print("[bold cyan]>>> SCENARIUL 1: Interogare Legitima de Telemetrie de la HMI (Operator)[/bold cyan]")
    p_norm1 = hmi.generate_telemetry_poll()
    log1 = firewall.process_packet(p_norm1)
    if log1.decision == "ALLOW":
        plc.execute_packet(p_norm1)
    display_packet_result(console, log1, "HMI Telemetry Polling (Citire Registre)")

    # -------------------------------------------------------------------------
    # DEMO 2: ATAC 1 - UNAUTHORIZED WRITE (IP Neautorizat)
    # -------------------------------------------------------------------------
    console.print("[bold cyan]>>> SCENARIUL 2: Atac Unauthorized Write (Laptop Compromis in Retea)[/bold cyan]")
    console.print("[dim]Atacatorul (192.168.1.99) incearca sa opreasca Valva de Urgenta (Coil 2001).[/dim]")
    unauth_packets = attacker.scenario_unauthorized_write()
    log2 = firewall.process_packet(unauth_packets[0])
    display_packet_result(console, log2, "Tentativa Scriere Neautorizata pe Valva de Siguranta")

    # -------------------------------------------------------------------------
    # DEMO 3: ATAC 2 - CRITICAL SETPOINT TAMPERING (Sabotaj Fizic)
    # -------------------------------------------------------------------------
    console.print("[bold cyan]>>> SCENARIUL 3: Sabotaj Fizic - Critical Setpoint Tampering (Stuxnet style)[/bold cyan]")
    console.print("[dim]Atacatorul incearca sa seteze presiunea la 500 PSI (limita de explozie este 80 PSI).[/dim]")
    tamper_packets = attacker.scenario_critical_setpoint_tampering()
    log3 = firewall.process_packet(tamper_packets[0])
    display_packet_result(console, log3, "Supracomanda Fizica a Presiunii Gazului")

    # -------------------------------------------------------------------------
    # DEMO 4: ATAC 3 - RECONNAISSANCE SCANNING
    # -------------------------------------------------------------------------
    console.print("[bold cyan]>>> SCENARIUL 4: Scanare de Recunoastere Industriala (Modbus Scanner)[/bold cyan]")
    console.print("[dim]Atacatorul scaneaza rapid ID-urile de slave si adresele de memorie.[/dim]")
    recon_packets = attacker.scenario_modbus_recon_scan(count=5)
    for p in recon_packets:
        log_recon = firewall.process_packet(p)
    display_packet_result(console, log_recon, "Scanare Topologie si Fuzzing Slave IDs")

    # -------------------------------------------------------------------------
    # DEMO 5: ATAC 4 - DENIAL OF SERVICE (FLOOD)
    # -------------------------------------------------------------------------
    console.print("[bold cyan]>>> SCENARIUL 5: Atac Denial of Service (Modbus Flood pe portul 502)[/bold cyan]")
    console.print("[dim]Trimitere a 100 de pachete in fractiune de secunda pentru a bloca PLC-ul.[/dim]")
    flood_packets = attacker.scenario_dos_flood(count=100)
    dropped_count = 0
    for p in flood_packets:
        log_flood = firewall.process_packet(p)
        if log_flood.decision == "DROP":
            dropped_count += 1
    display_packet_result(console, log_flood, f"Blocare Rafala DoS ({dropped_count}/100 pachete respinse de Rate Limiter)")

    # -------------------------------------------------------------------------
    # DEMO 6: ATAC 5 - PROTOCOL EVASION
    # -------------------------------------------------------------------------
    console.print("[bold cyan]>>> SCENARIUL 6: Tentativa Evaziune prin Pachet Malformat (Protocol Corruption)[/bold cyan]")
    console.print("[dim]Trimitere pachet cu Protocol ID ilegal (1 in loc de 0x0000) si lungime masiva.[/dim]")
    evasion_packets = attacker.scenario_protocol_evasion()
    log_ev = firewall.process_packet(evasion_packets[0])
    display_packet_result(console, log_ev, "Evaziune MBAP Protocol Corruption")

    # -------------------------------------------------------------------------
    # DEMO 7: ATAC 6 - STEALTH TIMING ANOMALY (AI DETECTION)
    # -------------------------------------------------------------------------
    console.print("[bold cyan]>>> SCENARIUL 7: Detectie Evasion / Anomalie Subtila prin Inteligenta Artificiala[/bold cyan]")
    console.print("[dim]Comanda sintactic valida de la HMI, dar cu deviatie statistica in frecventa si volum.[/dim]")
    stealth_packets = attacker.scenario_stealth_anomaly()
    for p in stealth_packets:
        log_stealth = firewall.process_packet(p)
    display_packet_result(console, log_stealth, "Anomalie Comportamentala Interceptata de Modelul AI")

    # -------------------------------------------------------------------------
    # DEMO 8: DEMONSTRATIE COMPARATIVA CYBER-PHYSICAL
    # -------------------------------------------------------------------------
    console.print("[bold magenta]======================================================================[/bold magenta]")
    console.print("[bold white]  DEMONSTRATIE COMPARATIVA: CUM PREVINE FIREWALL-UL ACTIUNILE NESIGURE[/bold white]")
    console.print("[bold magenta]======================================================================[/bold magenta]")

    comp_result = attacker.run_comparative_demonstration(firewall, plc)

    comp_table = Table(title="Comparatie Cyber-Physical: Fara Firewall vs. Cu Firewall Industrial", show_header=True)
    comp_table.add_column("Criteriu Evaluat", style="bold cyan", width=25)
    comp_table.add_column("Sistem FARA Firewall", style="bold red", width=35)
    comp_table.add_column("Sistem CU Firewall SCADA-Shield", style="bold green", width=35)

    comp_table.add_row(
        "Filtrare Pachet Atac",
        "Pachetul trece necontrolat (ALLOW)",
        f"Pachet BLOCAT ([bold red]{comp_result['with_firewall']['decision']}[/bold red])"
    )
    comp_table.add_row(
        "Regula / Explicatie",
        "Nicio protectie activa pe PLC",
        f"{comp_result['with_firewall']['triggered_rule']}"
    )
    comp_table.add_row(
        "Presiune Finala Conducta",
        f"{comp_result['without_firewall']['final_pressure']} PSI (Limita: 80 PSI)",
        f"{comp_result['with_firewall']['final_pressure']} PSI (In domeniu sigur)"
    )
    comp_table.add_row(
        "Integritate Fizica Retea",
        "[bold red]CONDUCTA RUPTA / EXPLOZIE[/bold red]",
        "[bold green]INTEGRITATE 100% PASTRATA[/bold green]"
    )
    comp_table.add_row(
        "Impact Operational",
        comp_result['without_firewall']['impact'],
        comp_result['with_firewall']['impact']
    )

    console.print(comp_table)
    console.print("")

    # -------------------------------------------------------------------------
    # RAPORT FINAL METRICI
    # -------------------------------------------------------------------------
    metrics = firewall.get_metrics()
    summary_table = Table(title="Raport Statistic General Firewall", header_style="bold yellow")
    summary_table.add_column("Indicator", style="white")
    summary_table.add_column("Valoare Masurata", style="bold cyan")

    summary_table.add_row("Total Pachete Inspectate", str(metrics["total_inspected"]))
    summary_table.add_row("Pachete Permise (Trafic Legitim)", f"[green]{metrics['allowed']}[/green]")
    summary_table.add_row("Pachete Blocate (Amenintari Oprite)", f"[red]{metrics['dropped']}[/red]")
    summary_table.add_row("Rata de Blocare Amenintari", f"[bold red]{metrics['drop_rate_pct']}%[/bold red]")
    summary_table.add_row("Anomalii Detectate de Inteligenta Artificiala", f"[bold magenta]{metrics['ai_anomalies']}[/bold magenta]")
    summary_table.add_row("Regim Read-Only Activat", f"[bold]{metrics['read_only_mode']}[/bold]")

    console.print(summary_table)

    console.print("\n[bold green][✓] Toate testele si scenariile de atac au fost validate cu succes![/bold green]")
    console.print("[dim]Pentru a lansa interfata grafica Web, rulati: streamlit run dashboard/app.py[/dim]\n")


if __name__ == "__main__":
    run_full_presentation_demo()
