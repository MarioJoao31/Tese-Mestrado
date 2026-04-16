from pathlib import Path

import PyInstaller.__main__


MCP_DIR = Path(__file__).resolve().parent.parent

PyInstaller.__main__.run([
    str(MCP_DIR / "interface.py"),
    "--onefile",
    "--name=mcp_dashboard",
    "--windowed",
    "--noconsole",
    f"--icon={MCP_DIR / 'build_tools' / 'assets' / 'attack-icon.icns'}",
    f"--specpath={MCP_DIR / 'build_tools'}",
    f"--distpath={MCP_DIR / 'build_tools' / 'dist'}",
    f"--workpath={MCP_DIR / 'build_tools' / 'build'}",
])
