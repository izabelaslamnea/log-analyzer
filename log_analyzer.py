
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import csv


LOG_FILE = "access.log"
REPORT_FILE = "security_report.csv"

FAILED_LOGIN = "FAILED"
SUCCESS_LOGIN = "SUCCESS"

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=2)
SUSPICIOUS_THRESHOLD = 3
SUSPICIOUS_WINDOW = timedelta(minutes=10)


def analyze_logs(filename):
    events = []
    failed_attempts = Counter()
    successful_logins = 0
    invalid_lines = 0

    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                parts = line.strip().split()

                if len(parts) != 4:
                    if line.strip():
                        invalid_lines += 1
                    continue

                date, time, ip, status = parts

                if status not in (FAILED_LOGIN, SUCCESS_LOGIN):
                    invalid_lines += 1
                    continue

                try:
                    timestamp = datetime.strptime(
                        f"{date} {time}", "%Y-%m-%d %H:%M:%S"
                    )
                except ValueError:
                    invalid_lines += 1
                    continue

                events.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "status": status
                })

                if status == FAILED_LOGIN:
                    failed_attempts[ip] += 1
                else:
                    successful_logins += 1

    except FileNotFoundError:
        print(f"Error: no se encuentra '{filename}'.")
        return

    events.sort(key=lambda event: event["timestamp"])

    events_by_ip = defaultdict(list)

    for event in events:
        events_by_ip[event["ip"]].append(event)

    alerts = []

    # Detectar posibles ataques de fuerza bruta
    for ip, ip_events in events_by_ip.items():
        failed_times = [
            event["timestamp"]
            for event in ip_events
            if event["status"] == FAILED_LOGIN
        ]

        for index, start_time in enumerate(failed_times):
            window_end = start_time + BRUTE_FORCE_WINDOW

            attempts = sum(
                1 for timestamp in failed_times
                if start_time <= timestamp <= window_end
            )

            if attempts >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": ip,
                    "risk": "ALTO",
                    "type": "Posible fuerza bruta",
                    "failed_attempts": attempts,
                    "details": (
                        f"{attempts} intentos fallidos en "
                        f"{BRUTE_FORCE_WINDOW.total_seconds() / 60:.0f} minutos"
                    )
                })
                break

    # Detectar fallos seguidos de un acceso correcto
    for ip, ip_events in events_by_ip.items():
        for index, event in enumerate(ip_events):
            if event["status"] != SUCCESS_LOGIN:
                continue

            start_time = event["timestamp"] - SUSPICIOUS_WINDOW

            previous_failures = sum(
                1 for previous in ip_events[:index]
                if previous["status"] == FAILED_LOGIN
                and start_time <= previous["timestamp"] < event["timestamp"]
            )

            if previous_failures >= SUSPICIOUS_THRESHOLD:
                alerts.append({
                    "timestamp": event["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": ip,
                    "risk": "MEDIO",
                    "type": "Fallos seguidos de acceso correcto",
                    "failed_attempts": previous_failures,
                    "details": (
                        f"{previous_failures} fallos antes del acceso correcto"
                    )
                })
                break

    # Evitar alertas duplicadas del mismo tipo e IP
    unique_alerts = {}
    for alert in alerts:
        key = (alert["ip"], alert["type"])
        unique_alerts[key] = alert

    alerts = list(unique_alerts.values())

    # Mostrar resumen
    print("\n========== SECURITY LOG ANALYZER ==========")
    print(f"Total de eventos válidos: {len(events)}")
    print(f"Accesos exitosos: {successful_logins}")
    print(f"Accesos fallidos: {sum(failed_attempts.values())}")
    print(f"IPs analizadas: {len(events_by_ip)}")
    print(f"Líneas inválidas: {invalid_lines}")

    print("\n========== ALERTAS DE SEGURIDAD ==========")

    if alerts:
        for alert in alerts:
            print(f"\n[{alert['risk']}] {alert['ip']}")
            print(f"Tipo: {alert['type']}")
            print(f"Detalle: {alert['details']}")
    else:
        print("No se han detectado patrones sospechosos.")

    # Exportar informe CSV
    with open(REPORT_FILE, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp",
                "ip",
                "risk",
                "type",
                "failed_attempts",
                "details"
            ]
        )
        writer.writeheader()
        writer.writerows(alerts)

    print(f"\nInforme generado: {REPORT_FILE}")


def main():
    print("========================================")
    print("          SECURITY LOG ANALYZER")
    print("========================================")

    analyze_logs(LOG_FILE)


if __name__ == "__main__":
    main()
