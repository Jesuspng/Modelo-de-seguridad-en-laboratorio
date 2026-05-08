# --- Librerías Estándar de Python ---
import os
import re
import csv
import time
import threading
import subprocess
from datetime import datetime
from collections import defaultdict

# --- Librerías de Terceros ---
import psutil
import pefile
import requests
from bs4 import BeautifulSoup
from plyer import notification

# ReportLab (Para generación de PDFs)
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Tkinter (Interfaz Gráfica)
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, Toplevel, Text, Scrollbar, END

# Scapy (Manipulación de Red)
import scapy.all as scapy
from scapy.all import sniff, ICMP, TCP, UDP, ARP
from scapy.layers.dns import DNS, DNSQR

import scapy.all as scapy
import requests
import time

# Diccionario para contar pings
ping_contador = defaultdict(list)
tcp_contador = defaultdict(list)
udp_contador = defaultdict(list)
historial_pings = []  # Lista global del historial de pings
### Lista para almacenar alertas detalladas
registro_alertas_detalladas = []
ultima_alerta_ip = None  # IP de la última alerta

# Umbrales
PING_UMBRAL = 1  # Número de pings para activar alerta
TCP_UMBRAL = 5
UDP_UMBRAL = 5
TIEMPO_UMBRAL = 10 # Tiempo en segundos para considerar pings excesivos

def mostrar_alerta_detallada(ip_origen):
    #------------------------------------------------
    global ultima_alerta_ip, registro_alertas_detalladas
    ultima_alerta_ip = ip_origen
    #------------------------------------------------
    
    mac = obtener_mac(ip_origen)
    fabricante = fabricante_por_mac(mac)
    #----------------------------------
    # Registrar alerta detallada
    hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    registro_alertas_detalladas.append({
    "hora": hora,
    "ip": ip_origen,
    "mac": mac,
    "fabricante": fabricante
})

    # Guardar en CSV
    with open("alertas_detalladas.csv", "a", newline="", encoding="utf-8") as f:
        escritor = csv.writer(f)
        escritor.writerow([hora, ip_origen, mac, fabricante])
    #---------------------------------
    ventana_alerta = tk.Toplevel()
    ventana_alerta.title("Alerta de Seguridad")
    ventana_alerta.geometry("460x300")

    hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mensaje = (
        f" Se detectó un posible ataque:\n\n"
        f" IP origen: {ip_origen}\n"
        f" Hora: {hora}\n"
        f" MAC: {mac}\n"
        f" Fabricante: {fabricante}\n\n"
        "Posible escaneo de red o intento de intrusión por exceso de pings."
    )
    tk.Label(ventana_alerta, text="ALERTA DETECTADA", fg="red", font=("Arial", 13, "bold")).pack(pady=10)
    tk.Label(ventana_alerta, text=mensaje, wraplength=420, justify="left").pack(pady=5)

    def bloquear_esta_ip():
        # Eliminar reglas anteriores si existen
        os.system(f'netsh advfirewall firewall delete rule name="Bloqueo automatico {ip_origen}"')
        os.system(f'netsh advfirewall firewall delete rule name="Bloqueo ICMP {ip_origen}"')

        # Regla general de bloqueo
        comando_general = f'netsh advfirewall firewall add rule name="Bloqueo automatico {ip_origen}" dir=in action=block remoteip={ip_origen} profile=any'
        resultado_general = os.system(comando_general)

        # Regla específica para bloquear pings (ICMP Echo Request)
        comando_icmp = f'netsh advfirewall firewall add rule name="Bloqueo ICMP {ip_origen}" protocol=icmpv4:8,any dir=in action=block remoteip={ip_origen} profile=any'
        #comando_icmp = f'netsh advfirewall firewall add rule name="Bloqueo ICMP {ip_origen}" protocol=icmpv4 direction=in action=block remoteip={ip_origen} profile=any interfacetype=any'

        resultado_icmp = os.system(comando_icmp)

        if resultado_general == 0 or resultado_icmp == 0:
            messagebox.showinfo("Bloqueo", f"La IP {ip_origen} ha sido bloqueada.")
            historial_pings.append((datetime.now().strftime("%H:%M:%S"), f" IP bloqueada automáticamente: {ip_origen}"))
            notification.notify(title="Bloqueo aplicado", message=f"{ip_origen} bloqueada.", timeout=2)
            ips_bloqueadas.add(ip_origen)
        else:
            messagebox.showerror("Error", "No se pudo bloquear la IP.")

#paquete
    def notificar_al_atacante():
        try:
            os.system(f"ping -n 1 {ip_origen}")
            messagebox.showinfo("Mensaje", "Se intentó enviar un mensaje al atacante (simulado con ping).")
        except:
            messagebox.showerror("Error", "No se pudo enviar mensaje.")

    tk.Button(ventana_alerta, text="Bloquear IP", bg="red", fg="white", command=bloquear_esta_ip).pack(pady=5)
    tk.Button(ventana_alerta, text="Notificar al atacante", bg="orange", command=notificar_al_atacante).pack(pady=5)
    tk.Button(ventana_alerta, text="Cerrar", command=ventana_alerta.destroy).pack(pady=5)

#nueva funcion 2#
def ver_historial_alertas_detalladas():
    ventana = tk.Toplevel()
    ventana.title("Historial de Alertas Detalladas")
    ventana.geometry("600x400")

    text = tk.Text(ventana, wrap=tk.WORD)
    text.pack(fill=tk.BOTH, expand=True)

    try:
        with open("alertas_detalladas.csv", "r", encoding="utf-8") as f:
            lector = csv.reader(f)
            filas = list(lector)

            if not filas:
                text.insert(tk.END, "No se han registrado alertas detalladas aún.")
                return

            for fila in filas:
                if len(fila) < 4:
                    continue
                hora, ip, mac, fabricante = fila
                text.insert(tk.END, f" Fecha: {hora}\n")
                text.insert(tk.END, f"     IP: {ip}\n")
                text.insert(tk.END, f"     MAC: {mac}\n")
                text.insert(tk.END, f"     Fabricante: {fabricante}\n\n")

    except FileNotFoundError:
        text.insert(tk.END, "No hay archivo de historial aún.")
    except Exception as e:
        text.insert(tk.END, f"Error al leer historial: {str(e)}")

#nueva funcion 2#
#nueva funcio 3#
def borrar_historial_alertas():
    global registro_alertas_detalladas
    if messagebox.askyesno("Confirmar", "¿Estás seguro de que deseas borrar TODO el historial de alertas detalladas?"):
        registro_alertas_detalladas = []
        try:
            if os.path.exists("alertas_detalladas.csv"):
                os.remove("alertas_detalladas.csv")
            messagebox.showinfo("Éxito", "Historial de alertas borrado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo borrar el archivo:\n{str(e)}")

#nueva funcion 3#
# nueva funcion #
def ver_ultima_alerta():
    if ultima_alerta_ip:
        mostrar_alerta_detallada(ultima_alerta_ip)
    else:
        messagebox.showinfo("Sin alertas", "No se ha detectado ninguna alerta aún.")
# nueva funcion #
# ----- Sniffer general -----
alertas_mostradas = {}  # {ip: timestamp_ultima_alerta}
TIEMPO_REPETICION_ALERTA = 60  # segundos
ips_bloqueadas = set()

def detectar_paquete(pkt):
    tiempo = datetime.now().strftime("%H:%M:%S")

    # Detección de ping (ICMP)
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        origen = pkt["IP"].src if pkt.haslayer("IP") else "Desconocido"
        if origen in ips_bloqueadas:
            return

        mensaje = f"Ping recibido de {origen} a las {tiempo}"
        print(mensaje)
        ping_contador[origen].append(time.time())
        ping_contador[origen] = [t for t in ping_contador[origen] if time.time() - t <= TIEMPO_UMBRAL]
        historial_pings.append((tiempo, mensaje))
        notification.notify(title="Ping detectado", message=mensaje, timeout=2)

        if len(ping_contador[origen]) >= PING_UMBRAL:
            ahora = time.time()
            if ahora - alertas_mostradas.get(origen, 0) > TIEMPO_REPETICION_ALERTA:
                alertas_mostradas[origen] = ahora
                alerta = f"Pings excesivos desde {origen}"
                historial_pings.append((tiempo, alerta))
                notification.notify(title="Alerta de Seguridad (ICMP)", message=alerta, timeout=5)
                mostrar_alerta_detallada(origen)

    # Detección de consultas DNS
    elif pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        dominio = pkt[DNSQR].qname.decode()
        origen = pkt["IP"].src if pkt.haslayer("IP") else "Desconocido"
        mensaje = f"Consulta DNS desde {origen}: {dominio}"
        historial_pings.append((tiempo, mensaje))
        print(mensaje)

        ahora = time.time()
        if ahora - alertas_mostradas.get(origen, 0) > TIEMPO_REPETICION_ALERTA:
            alertas_mostradas[origen] = ahora
            notification.notify(title="Consulta DNS detectada", message=mensaje, timeout=3)
            mostrar_alerta_detallada(origen)

    # Detección de paquetes TCP SYN
    elif pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
        origen = pkt["IP"].src
        puerto_destino = pkt[TCP].dport
        mensaje = f"Paquete TCP SYN detectado desde {origen} al puerto {puerto_destino}"
        print(mensaje)
        historial_pings.append((tiempo, mensaje))

        tcp_contador[origen].append(time.time())
        tcp_contador[origen] = [t for t in tcp_contador[origen] if time.time() - t <= TIEMPO_UMBRAL]

        if len(tcp_contador[origen]) >= TCP_UMBRAL:
            ahora = time.time()
            if ahora - alertas_mostradas.get(origen, 0) > TIEMPO_REPETICION_ALERTA:
                alertas_mostradas[origen] = ahora
                alerta = f"Conexiones TCP sospechosas desde {origen} al puerto {puerto_destino}"
                historial_pings.append((tiempo, alerta))
                notification.notify(title="Alerta TCP", message=alerta, timeout=5)
                mostrar_alerta_detallada(origen)

    # Detección de paquetes UDP
    elif pkt.haslayer(UDP):
        origen = pkt["IP"].src
        puerto_destino = pkt[UDP].dport
        mensaje = f"Paquete UDP detectado desde {origen} al puerto {puerto_destino}"
        print(mensaje)
        historial_pings.append((tiempo, mensaje))
        notification.notify(title="Paquete UDP detectado", message=mensaje, timeout=2)

        udp_contador[origen].append(time.time())
        udp_contador[origen] = [t for t in udp_contador[origen] if time.time() - t <= TIEMPO_UMBRAL]

        if len(udp_contador[origen]) >= UDP_UMBRAL:
            ahora = time.time()
            if ahora - alertas_mostradas.get(origen, 0) > TIEMPO_REPETICION_ALERTA:
                alertas_mostradas[origen] = ahora
                alerta = f"Paquetes UDP sospechosos desde {origen} al puerto {puerto_destino}"
                historial_pings.append((tiempo, alerta))
                notification.notify(title="Alerta UDP", message=alerta, timeout=5)
                mostrar_alerta_detallada(origen)
# ----- Funciones de red -----
def mostrar_conexiones():
    ventana = tk.Toplevel()
    ventana.title("Conexiones activas")
    ventana.geometry("800x480")

    tree = ttk.Treeview(ventana, columns=("Local", "Remoto", "Estado", "PID", "Proceso"), show="headings")
    for col in tree["columns"]:
        tree.heading(col, text=col)
        tree.column(col, width=140, anchor=tk.W)
    tree.pack(fill=tk.BOTH, expand=True)

    for conn in psutil.net_connections():
        if not conn.raddr:
            continue  # ignorar si no hay IP remota

        ip_remota = conn.raddr.ip
        if ip_remota.startswith("127.") or ip_remota.startswith("::1"):
            continue  # ignorar loopback/localhost

        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
        pid = conn.pid or "-"
        try:
            proceso = psutil.Process(conn.pid).name() if conn.pid else "-"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proceso = "Acceso denegado"
        tree.insert("", tk.END, values=(laddr, raddr, conn.status, pid, proceso))

    proceso_label = tk.Label(ventana, text="Proceso: (ninguno)", fg="blue", font=("Arial", 10, "italic"))
    proceso_label.pack(pady=5)

    def al_seleccionar(event):
        item = tree.focus()
        if not item:
            proceso_label.config(text="Proceso: (ninguno)")
            return
        nombre = tree.item(item, "values")[4]
        proceso_label.config(text=f"Proceso: {nombre}")
    
 
    
    ips_bloqueadas_runtime = set()

    def cargar_ips_bloqueadas():
        try:
            resultado = subprocess.run('netsh advfirewall firewall show rule name=all', shell=True, capture_output=True, text=True)
            reglas = resultado.stdout

            # Buscar todas las líneas que contengan una IP remota
            ips = re.findall(r'RemoteIP:\s*([\d\.]+)', reglas)

            for ip in ips:
                ips_bloqueadas_runtime.add(ip)
            print(f"[+] IPs cargadas desde el firewall: {ips}")
        except Exception as e:
            print(f"[!] Error al cargar IPs del firewall: {str(e)}")

    cargar_ips_bloqueadas()

    def bloquear_ip():
        item = tree.focus()
        if not item:
            messagebox.showwarning("Advertencia", "Selecciona una conexión.")
            return

        valores = tree.item(item, "values")
        ip_remota = valores[1].split(":")[0]

        if ip_remota and not ip_remota.startswith("127"):
            if messagebox.askyesno("Confirmar", f"¿Deseas bloquear la IP {ip_remota}?"):
                comando = f'netsh advfirewall firewall add rule name="Bloqueo {ip_remota}" dir=in action=block remoteip={ip_remota}'
                resultado = os.system(comando)
                if resultado == 0:
                    historial_pings.append((datetime.now().strftime("%H:%M:%S"), f" IP bloqueada manualmente: {ip_remota}"))
                    ips_bloqueadas_runtime.add(ip_remota)  # <-- Añade aquí la IP al set de bloqueadas
                    messagebox.showinfo("Éxito", f"La IP {ip_remota} ha sido bloqueada.")
                else:
                    messagebox.showerror("Error", "No se pudo bloquear la IP.")
        else:
            messagebox.showwarning("Advertencia", "No se detectó una IP remota válida.")

    tree.bind("<ButtonRelease-1>", al_seleccionar)

    tk.Button(ventana, text="Bloquear IP seleccionada", command=bloquear_ip).pack(pady=5)
    scrollbar = ttk.Scrollbar(ventana, orient="vertical", command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

def mostrar_ips_bloqueadas():
    ventana = tk.Toplevel()
    ventana.title("IPs Bloqueadas por la aplicación")
    ventana.geometry("500x400")

    lista_ips = tk.Listbox(ventana)
    lista_ips.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def cargar_ips():
        lista_ips.delete(0, tk.END)
        try:
            salida = subprocess.check_output(
                'netsh advfirewall firewall show rule name=all',
                shell=True, text=True
            )

            reglas = salida.split("-------------------------------------------------------------------")
            bloqueos = []

            for regla in reglas:
                if "Bloqueo" in regla:
                    lineas = regla.splitlines()
                    nombre = ""
                    ip = ""

                    for linea in lineas:
                        if linea.strip().startswith("Nombre de regla"):
                            nombre = linea.split(":")[1].strip()
                        if "RemoteIP" in linea:
                            ip = linea.split(":")[1].strip()

                    if nombre and ip:
                        bloqueos.append((nombre, ip))

            if bloqueos:
                for nombre, ip in bloqueos:
                    lista_ips.insert(tk.END, f"{nombre} → {ip}")
            else:
                lista_ips.insert(tk.END, "No hay reglas creadas por esta aplicación.")

        except subprocess.CalledProcessError:
            lista_ips.insert(tk.END, "Error al obtener las reglas del firewall.\n¿Ejecutaste como administrador?")
        except Exception as e:
            lista_ips.insert(tk.END, f"Error inesperado: {str(e)}")

    def eliminar_regla():
        seleccion = lista_ips.curselection()
        if not seleccion:
            messagebox.showwarning("Advertencia", "Selecciona una IP para desbloquear.")
            return

        texto = lista_ips.get(seleccion[0])
        nombre = texto.split("→")[0].strip()  # Nombre completo de la regla
        ip = texto.split("→")[1].strip()      # IP exacta, de la parte derecha

        if messagebox.askyesno("Confirmar", f"¿Deseas desbloquear la IP '{nombre}'?"):
            comando = f'netsh advfirewall firewall delete rule name="{nombre}"'
            resultado = os.system(comando)
            if resultado == 0:
                # Permitir ICMP entrante y saliente para esa IP
                os.system(f'netsh advfirewall firewall add rule name="Allow ICMPv4-In {ip}" protocol=icmpv4:8,any dir=in action=allow remoteip={ip} profile=any')
                os.system(f'netsh advfirewall firewall add rule name="Allow ICMPv4-Out {ip}" protocol=icmpv4:0,any dir=out action=allow remoteip={ip} profile=any')

                historial_pings.append((datetime.now().strftime("%H:%M:%S"), f" Regla eliminada: {nombre}"))
                messagebox.showinfo("Éxito", f"IP '{nombre}' eliminada correctamente.")
                cargar_ips()
            else:
                messagebox.showerror("Error", f"No se pudo desbloquear la IP '{nombre}'.")


    btn_eliminar = tk.Button(ventana, text="Desbloquear IP", command=eliminar_regla)
    btn_eliminar.pack(pady=5)

    cargar_ips()
#notificacion--------------------------------------------------------------------------------------------------------#

stop_event = threading.Event()
sniffer_thread = None  # Variable global para el hilo del sniffer

def iniciar_sniffer():
    print("[+] Sniffer ICMP/ARP activo. Esperando paquetes...")
    try:
        # Usar el Event para detener el sniffer
        sniff(filter="icmp or arp", prn=detectar_paquete, store=0, stop_filter=lambda x: stop_event.is_set())
    except PermissionError:
        print("[ERROR] Debes ejecutar este script como administrador.")

def reiniciar_sniffer():
    global sniffer_thread
    # Detener el sniffer actual
    stop_event.set()
    if sniffer_thread and sniffer_thread.is_alive():
        sniffer_thread.join(timeout=1)  # Esperar a que el hilo termine

    # Iniciar un nuevo sniffer
    stop_event.clear()
    sniffer_thread = threading.Thread(target=iniciar_sniffer, daemon=True)
    sniffer_thread.start()

def desbloquear_ip_manual():
    def desbloquear():
        ip = entrada.get().strip()
        if not ip:
            messagebox.showwarning("Advertencia", "Ingresa una IP válida.")
            return
        try:
            # Obtener todas las reglas que contengan la IP
            salida = subprocess.check_output('netsh advfirewall firewall show rule name=all', shell=True, text=True)
            reglas = salida.split('-------------------------------------------------------------------')
            reglas_eliminadas = 0
            for regla in reglas:
                if ip in regla:
                    for linea in regla.splitlines():
                        if linea.strip().startswith("Nombre de regla"):
                            nombre = linea.split(":",1)[1].strip()
                            comando_eliminar = f'netsh advfirewall firewall delete rule name="{nombre}"'
                            resultado = os.system(comando_eliminar)
                            if resultado == 0:
                                reglas_eliminadas += 1
            # Permitir que entren respuestas desde esa IP
            comando_in = f'netsh advfirewall firewall add rule name="Permitir ICMP Echo In {ip}" protocol=icmpv4:0,any dir=in action=allow remoteip={ip} profile=any'
            res_in = os.system(comando_in)
            # Permitir que salgan peticiones hacia esa IP
            comando_out = f'netsh advfirewall firewall add rule name="Permitir ICMP Echo Out {ip}" protocol=icmpv4:8,any dir=out action=allow remoteip={ip} profile=any'
            res_out = os.system(comando_out)
            # Permitir pings entrantes en general (como refuerzo)
            os.system('netsh advfirewall firewall add rule name="Allow ICMPv4-In" protocol=icmpv4:8,any dir=in action=allow')
            if reglas_eliminadas > 0 and res_in == 0 and res_out == 0:
                messagebox.showinfo("Desbloqueo", f"La IP {ip} fue desbloqueada y permitido tráfico ICMP.")
                ventana.destroy()
                # Reiniciar el sniffer
                reiniciar_sniffer()
            else:
                messagebox.showwarning("Aviso", f"No se encontraron reglas previas para {ip} o hubo problemas al crear reglas ICMP.\nAún así se intentó desbloquear y permitir ICMP.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo desbloquear la IP:\n{str(e)}")

    ventana = tk.Toplevel()
    ventana.title("Desbloquear IP")
    ventana.geometry("320x150")
    tk.Label(ventana, text="Ingresa la IP a desbloquear:").pack(pady=10)
    entrada = tk.Entry(ventana)
    entrada.pack()
    tk.Button(ventana, text="Desbloquear", command=desbloquear).pack(pady=10)
#notificacion--------------------------------------------------------------------------------------------------------#
def verificar_bloqueo_ip():
    def verificar():
        ip = entrada.get()
        if not ip:
            messagebox.showwarning("Advertencia", "Ingresa una IP.")
            return
        try:
            salida = subprocess.check_output(
                'netsh advfirewall firewall show rule name=all',
                shell=True, text=True
            )
            if ip in salida:
                resultado.config(text=f"La IP {ip} está BLOQUEADA ", fg="red")
            else:
                resultado.config(text=f"La IP {ip} NO está bloqueada ", fg="green")
        except subprocess.CalledProcessError:
            resultado.config(text="Error al verificar las reglas del firewall.", fg="orange")
        except Exception as e:
            resultado.config(text=f"Error inesperado: {str(e)}", fg="orange")

    ventana = tk.Toplevel()
    ventana.title("Verificar bloqueo de IP")
    ventana.geometry("400x180")

    tk.Label(ventana, text="Ingresa la IP a verificar:").pack(pady=10)
    entrada = tk.Entry(ventana)
    entrada.pack()

    tk.Button(ventana, text="Verificar", command=verificar).pack(pady=10)
    resultado = tk.Label(ventana, text="", font=("Arial", 11, "bold"))
    resultado.pack(pady=5)

def mostrar_historial():
    ventana = tk.Toplevel()
    ventana.title("Historial de eventos")
    ventana.geometry("500x400")

    lista = tk.Text(ventana)
    lista.pack(fill=tk.BOTH, expand=True)

    # Filtrar solo los eventos de ping
    for hora, evento in historial_pings:
        if "Ping recibido" in evento:
            lista.insert(tk.END, f"[{hora}] {evento}\n\n")

    def limpiar():
        # Limpiar solo los eventos de ping del historial
        global historial_pings
        historial_pings = [(hora, evento) for hora, evento in historial_pings if "Ping recibido" not in evento]
        lista.delete("1.0", tk.END)

    tk.Button(ventana, text="Limpiar historial", command=limpiar).pack(pady=5)
    


def exportar_alertas_pdf():
    if not registro_alertas_detalladas:
        messagebox.showinfo("Sin datos", "No hay alertas detalladas para exportar.")
        return

    archivo = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
    if not archivo:
        return

    try:
        c = canvas.Canvas(archivo, pagesize=letter)
        c.setFont("Helvetica", 10)
        width, height = letter
        y = height - 50
        c.drawString(50, y, "Historial de Alertas Detalladas")
        y -= 30

        for i, alerta in enumerate(registro_alertas_detalladas, start=1):
            if y < 80:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 50

            hora = alerta.get("hora", "N/A")
            ip = alerta.get("ip", "N/A")
            mac = alerta.get("mac", "N/A")
            fabricante = alerta.get("fabricante", "N/A")

            c.drawString(50, y, f"{i}. IP: {ip}")
            y -= 15
            c.drawString(60, y, f"   Hora: {hora}")
            y -= 15
            c.drawString(60, y, f"   MAC: {mac}")
            y -= 15
            c.drawString(60, y, f"   Fabricante: {fabricante}")
            y -= 25

        c.save()
        messagebox.showinfo("Éxito", f"PDF guardado exitosamente en:\n{archivo}")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo exportar:\n{str(e)}")



#----- Esto ya es aparte APK-----------------------------------------------------------------------------------------------------#
#Esto es del .exe ---------------------------------------------------------------------------------------------------------------#


def analizar_exe_simple():
    archivo_exe = filedialog.askopenfilename(filetypes=[("Ejecutables de Windows", "*.exe")])
    if not archivo_exe:
        return

    try:
        pe = pefile.PE(archivo_exe)
        info = f"Archivo: {archivo_exe}\n\n"

        info += f"Entrypoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n"
        info += f"ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}\n"
        info += f"Número de secciones: {len(pe.sections)}\n\n"

        info += "Secciones:\n"
        for section in pe.sections:
            info += f"  - {section.Name.decode().strip()} | Tamaño: {hex(section.SizeOfRawData)}\n"

        ventana = tk.Toplevel()
        ventana.title("Análisis de EXE")
        ventana.geometry("600x400")
        text = tk.Text(ventana, wrap=tk.WORD)
        text.insert(tk.END, info)
        text.pack(fill=tk.BOTH, expand=True)

    except Exception as e:
        messagebox.showerror("Error", f"No se pudo analizar el EXE:\n{str(e)}")

#Esto es del .exe ---------------------------------------------------------------------------------------------------------------#
#-----Esto es otro aparte, ver ip expuestas, para saber si la red  esta expuesta-------------------------------------------------------------------------------------#


def buscar_en_shodan_sin_api(ip):
    try:
        url = f"https://www.shodan.io/host/{ip}"
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            data = {"ip": ip, "puertos": [], "detalles": []}

            for servicio in soup.select(".port"):
                puerto = servicio.get_text(strip=True)
                if puerto:
                    data["puertos"].append(puerto)

            for entry in soup.select(".service"):
                servicio_texto = entry.get_text(strip=True)
                if servicio_texto:
                    data["detalles"].append(servicio_texto)

            return data
        elif response.status_code == 404:
            return {"error": f"No se encontraron resultados para {ip} en Shodan."}
        else:
            return {"error": f"Error al consultar Shodan (Código {response.status_code})"}
    except Exception as e:
        return {"error": f"Excepción: {str(e)}"}

def obtener_ip_publica():
    try:
        respuesta = requests.get("https://api.ipify.org")
        if respuesta.status_code == 200:
            return respuesta.text.strip()
        else:
            return None
    except:
        return None

def ventana_shodan_detallada():
    ventana = Toplevel()
    ventana.title("Análisis con Shodan")
    ventana.geometry("650x500")

    text = Text(ventana, wrap=tk.WORD)
    text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = Scrollbar(ventana, command=text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text.config(yscrollcommand=scrollbar.set)

    text.insert(END, " Detectando IP pública...\n")
    ventana.update()

    ip_publica = obtener_ip_publica()

    if not ip_publica:
        text.insert(END, "\n No se pudo obtener la IP pública.\n")
        return

    text.insert(END, f"\n IP pública detectada: {ip_publica}\n")
    text.insert(END, "\n Consultando Shodan...\n")
    ventana.update()

    resultado = buscar_en_shodan_sin_api(ip_publica)

    if "error" in resultado:
        text.insert(END, f"\n Error: {resultado['error']}\n")
        return

    text.insert(END, f"\n Resultados para {ip_publica}:\n\n")

    if resultado["puertos"]:
        text.insert(END, " Puertos abiertos detectados:\n")
        for puerto in resultado["puertos"]:
            text.insert(END, f"  - {puerto}\n")
    else:
        text.insert(END, "No se detectaron puertos abiertos.\n")

    if resultado["detalles"]:
        text.insert(END, "\n Servicios expuestos:\n")
        for detalle in resultado["detalles"]:
            text.insert(END, f"  - {detalle}\n")

    else:
        text.insert(END, "No se detectaron servicios específicos.\n")
#-----Esto es otro aparte, ver ip expuestas -------------------------------------------------------------------------------------#
#nuevas funciones que menciono el profe------------------------------------------------------------------------------------------#


def obtener_mac(ip_objetivo):
    # Creamos el paquete ARP
    arp_request = scapy.ARP(pdst=ip_objetivo)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = broadcast / arp_request
    
    # srp devuelve (respondidos, no respondidos)
    # Aumentamos un poco el timeout por si la red es lenta
    respuesta = scapy.srp(paquete, timeout=3, verbose=False)[0]

    if respuesta:
        # respuesta[0][1] es el primer paquete recibido
        return respuesta[0][1].hwsrc 
    else:
        return None

def fabricante_por_mac(mac):
    if not mac:
        return "N/A"
    try:
        # Limpiamos la MAC para la API
        prefijo = mac.upper().replace(":", "")[:6]
        url = f"https://api.macvendors.com/{prefijo}"
        
        # Respetamos el límite de la API gratuita
        time.sleep(1) 
        
        respuesta = requests.get(url, timeout=5)
        if respuesta.status_code == 200:
            return respuesta.text
        else:
            return "Fabricante desconocido"
    except Exception as e:
        return f"Error: {e}"

#nuevas funciones que menciono el profe-----------------------------------------------------------------------------------------#
def crear_ventana_principal():
    root = tk.Tk()
    root.title("Monitor de Red")
    root.geometry("320x400")

    tk.Label(root, text="Detección de Red", font=("Arial", 14, "bold")).pack(pady=10)

    botones = [
        ("Ver conexiones activas", mostrar_conexiones),
        ("Ver historial de eventos", mostrar_historial),
        ("Ver IPs bloqueadas", mostrar_ips_bloqueadas),
        ("Desbloquear IP manualmente", desbloquear_ip_manual),
        ("Verificar si IP está bloqueada", verificar_bloqueo_ip),
        #aparte#
        #("Analizar APK", analizar_apk_simple),
        #aparte#
        #aparte2#
        ("Revisar exposición de IP pública", ventana_shodan_detallada),
        #aparte2#
        #aparte3#
        ("Ver última alerta detallada", ver_ultima_alerta),
        #aparte3#
        #aparte4#
        ("Ver historial de alertas detalladas", ver_historial_alertas_detalladas),
        #aparte4#
        #aparte 5#
        ("Borrar historial de alertas detalladas", borrar_historial_alertas),
        #aparte 5#
        #aparte6#
        ("Exportar alertas a PDF", exportar_alertas_pdf),
        #aparte6#
        #aparte7#
        ("Analizar EXE", analizar_exe_simple),
        #aparte7#
        ("Salir", root.destroy),
    ]

    for texto, accion in botones:
        tk.Button(root, text=texto, width=30, command=accion).pack(pady=6)

    threading.Thread(target=iniciar_sniffer, daemon=True).start()
    root.mainloop()

crear_ventana_principal()