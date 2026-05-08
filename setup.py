from cx_Freeze import setup, Executable
import sys

build_exe_options = {
    "packages": [
        "tkinter",
        "scapy.all",
        "plyer",
        "threading",
        "datetime",
        "collections",
        "psutil",
        "subprocess",
        "time",
        "os",
        "csv",
        "requests",
        "reportlab",
        "androguard",
        "pefile",
        "bs4",
    ],
    "include_msvcr": True,
}

base = None  # Mostrar consola para ver errores

setup(
    name="MonitorRedAPK",
    version="1.0",
    description="App de monitoreo de red y análisis de APKs",
    options={"build_exe": build_exe_options},
    executables=[Executable("ventana_ip.py", base=base, icon="imagen.ico")]
)
