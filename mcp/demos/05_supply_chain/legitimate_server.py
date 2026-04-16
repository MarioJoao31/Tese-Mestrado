"""
05_supply_chain/legitimate_server.py
--------------------------------------
Servidor MCP LEGÍTIMO — fornece ferramentas de gestão de ficheiros.

Este servidor é o que o programador espera estar a usar.
Interface pública:
  - file_read   : Lê um ficheiro
  - file_write  : Escreve um ficheiro
  - file_list   : Lista ficheiros
  - file_hash   : Calcula o hash SHA-256 de um ficheiro
"""

import os
import hashlib
import json
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Legitimate File Tools v1.0")

_WORKSPACE = os.path.join(os.path.dirname(__file__), "workspace_legit")


def _safe_path(filename: str) -> str | None:
    """Valida e devolve o caminho absoluto dentro do workspace."""
    os.makedirs(_WORKSPACE, exist_ok=True)
    requested = os.path.abspath(os.path.join(_WORKSPACE, filename))
    if not requested.startswith(_WORKSPACE + os.sep) and requested != _WORKSPACE:
        return None
    return requested


# ---------------------------------------------------------------------------
# Ferramentas
# ---------------------------------------------------------------------------

@mcp.tool()
def file_read(filename: str) -> str:
    """
    Lê o conteúdo de um ficheiro no workspace.

    Args:
        filename: Nome do ficheiro a ler.

    Returns:
        Conteúdo do ficheiro.
    """
    path = _safe_path(filename)
    if path is None:
        return "Erro: acesso negado."
    if not os.path.isfile(path):
        return f"Erro: ficheiro '{filename}' não encontrado."
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


@mcp.tool()
def file_write(filename: str, content: str) -> str:
    """
    Escreve conteúdo num ficheiro no workspace.

    Args:
        filename: Nome do ficheiro.
        content:  Conteúdo a escrever.

    Returns:
        Confirmação.
    """
    path = _safe_path(filename)
    if path is None:
        return "Erro: acesso negado."
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return f"Ficheiro '{filename}' escrito ({len(content)} bytes)."


@mcp.tool()
def file_list() -> str:
    """
    Lista os ficheiros no workspace.

    Returns:
        Lista de ficheiros em formato JSON.
    """
    os.makedirs(_WORKSPACE, exist_ok=True)
    files = os.listdir(_WORKSPACE)
    return json.dumps(sorted(files))


@mcp.tool()
def file_hash(filename: str) -> str:
    """
    Calcula o hash SHA-256 de um ficheiro.

    Args:
        filename: Nome do ficheiro.

    Returns:
        Hash SHA-256 em hexadecimal.
    """
    path = _safe_path(filename)
    if path is None:
        return "Erro: acesso negado."
    if not os.path.isfile(path):
        return f"Erro: ficheiro '{filename}' não encontrado."
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
