import asyncio
import os
import sqlite3
import subprocess
import tempfile
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Response

latest_scan_result = ""

async def nmap_scan():
    global latest_scan_result

    while True:
        print("Scan beginning")
        # Подключаемся к базе и получаем активные хосты
        con = sqlite3.connect("sqlite.db")
        cur = con.cursor()
        res = cur.execute("SELECT hostname FROM hosts WHERE state = 1")
        active_hosts = [row[0] for row in res.fetchall()]
        con.close()

        if not active_hosts:
            latest_scan_result = "No active hosts to scan"
            await asyncio.sleep(30)
            continue

        # Создаем временный файл с хостами для nmap -iL
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('\n'.join(active_hosts))
            temp_filename = f.name

        # Запускаем nmap для всех хостов сразу
        try:
            result = subprocess.run(
                ["nmap", "-F", "-sV", "-iL", temp_filename],
                capture_output=True,
                text=True
            )
            latest_scan_result = result.stdout
        finally:
            os.unlink(temp_filename)  # Удаляем временный файл

        await asyncio.sleep(60)  # Ждем 5 минут

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Запускаем фоновую задачу при старте
    task = asyncio.create_task(nmap_scan())
    yield
    # Останавливаем при завершении (если нужно)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

app = FastAPI(lifespan=lifespan)

con = sqlite3.connect("sqlite.db")
cur = con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS hosts(hostname, state, description)")
con.close()

@app.post("/add_host/")
async def add_host(hostname: str, state: bool, description: str):
    con = sqlite3.connect("sqlite.db")
    cur = con.cursor()

    # Проверяем существование hostname
    cur.execute("SELECT 1 FROM hosts WHERE hostname = ?", (hostname,))
    if cur.fetchone():
        con.close()
        return {"error": "Hostname already exists"}
        # return {"status": False, "error": "Hostname already exists"}

    data = [(hostname, state, description)]
    cur.executemany("INSERT INTO hosts VALUES(?, ?, ?)", data)

    con.commit()
    con.close()

    return {"hostname": hostname, "status": state, "description": description}

@app.get("/get_hosts/")
async def get_hosts():
    con = sqlite3.connect("sqlite.db")
    cur = con.cursor()

    res = cur.execute("SELECT hostname, state, description FROM hosts")
    hosts = res.fetchall()

    con.close()

    return {"hosts": hosts}

@app.get("/metrics")
async def get_metrics():

    # Initialize metrics string
    #metrics = "# HELP nmap_port_scan Nmap port scan results\n# TYPE nmap_port_scan gauge\n"
    metrics = "# TYPE nmap_port_scan gauge\n"

    current_host = None
    current_ip = None

    for line in latest_scan_result.split('\n'):
        line = line.strip()

        # Parse host and IP
        if line.startswith("Nmap scan report for"):
            parts = line.split()
            if '(' in line and ')' in line:
                host_start = line.find("for ") + 4
                host_end = line.find(" (")
                current_host = line[host_start:host_end]
                ip_start = line.find("(") + 1
                ip_end = line.find(")")
                current_ip = line[ip_start:ip_end]
            else:
                current_host = parts[-1]
                current_ip = parts[-1]

        # Skip non-port lines
        elif line.startswith(('PORT ', 'Not shown:', 'Host is up', 'Other addresses', 'Service Info', 'MAC Address')):
            continue

        # Parse port lines
        elif '/' in line and 'tcp' in line and (line.split()[1] in ['open', 'filtered', 'closed']):
            parts = line.split()
            port_info = parts[0].split('/')
            port = port_info[0]
            protocol = port_info[1]
            state = parts[1]
            service = parts[2] if len(parts) > 2 else 'unknown'

            # Extract version (everything after service name)
            version = 'unknown'
            if len(parts) > 3:
                version = ' '.join(parts[3:])
                # Clean up version string
                version = version.replace('"', '').replace("'", "")

            # Add to metrics
            metrics += f'nmap_port_scan{{host="{current_host}", ip="{current_ip}", port="{port}", protocol="{protocol}", state="{state}", service="{service}", version="{version}"}} 1\n'

    print(metrics)

    #return metrics
    return Response(content=metrics, media_type="text/plain")
    # return latest_scan_result

@app.post("/toggle_host_status/")
async def toggle_host_status(hostname: str):
    con = sqlite3.connect("sqlite.db")
    cur = con.cursor()

    # Проверяем существование хоста
    cur.execute("SELECT state FROM hosts WHERE hostname = ?", (hostname,))
    result = cur.fetchone()
    if not result:
        return {"status": False, "error": "Host not found"}

    # Меняем статус на противоположный
    new_state = not result[0]
    cur.execute("UPDATE hosts SET state = ? WHERE hostname = ?", (new_state, hostname))
    con.commit()

    con.close()

    return {"status": True, "hostname": hostname, "new_state": new_state}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", reload=True)