import PyInstaller.__main__ 

PyInstaller.__main__.run([
    "interface.py",
    "--onefile",
    "--name=mcp_dashboard",
    "--windowed",
    "--noconsole",
    "--icon=assets/attack-icon.icns",
])