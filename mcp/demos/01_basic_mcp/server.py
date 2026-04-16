"""
01_basic_mcp/server.py
----------------------
Servidor MCP simples com ferramentas de segurança básicas.

Este servidor é lançado pelo client.py via stdio transport —
não precisa de ser executado manualmente.

Ferramentas disponíveis:
  - calculate            : avalia expressões matemáticas (whitelist de chars)
  - read_file            : lê ficheiros dentro de ./data/ (path traversal safe)
  - check_password_strength : analisa a força de uma password
  - get_system_info      : informação básica do sistema (só leitura)
  - scan_text_for_injection : detecta padrões de prompt injection
"""

import os
import re
import platform
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Basic Security Tools")

# ---------------------------------------------------------------------------
# Ferramenta 1 — Calculadora segura
# ---------------------------------------------------------------------------

@mcp.tool()
def calculate(expression: str) -> str:
    """
    Avalia uma expressão matemática simples.

    Apenas permite: dígitos, espaços e os operadores + - * / ( ) .
    Qualquer outro caracter é rejeitado para evitar injeção de código.

    Args:
        expression: Expressão matemática, e.g. "(3 + 5) * 2"

    Returns:
        Resultado como string, ou mensagem de erro.
    """
    if not re.match(r"^[\d\s\+\-\*\/\(\)\.]+$", expression):
        return "Erro: apenas operações matemáticas básicas são permitidas."
    try:
        result = eval(expression)  # seguro graças à whitelist acima
        return str(result)
    except Exception as exc:
        return f"Erro ao avaliar expressão: {exc}"


# ---------------------------------------------------------------------------
# Ferramenta 2 — Leitura de ficheiros (path traversal safe)
# ---------------------------------------------------------------------------

@mcp.tool()
def read_file(path: str) -> str:
    """
    Lê o conteúdo de um ficheiro dentro da pasta ./data/.

    A ferramenta rejeita qualquer caminho fora do directório autorizado
    para prevenir ataques de path traversal (e.g. ../../etc/passwd).

    Args:
        path: Caminho relativo ao directório ./data/, e.g. "notes.txt"

    Returns:
        Conteúdo do ficheiro, ou mensagem de erro.
    """
    # Resolve o directório base de forma absoluta
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
    # Resolve o caminho pedido e verifica se está dentro do base_dir
    requested = os.path.abspath(os.path.join(base_dir, path))

    if not requested.startswith(base_dir + os.sep) and requested != base_dir:
        return "Erro: acesso negado — o caminho tem de estar dentro de ./data/."

    if not os.path.isfile(requested):
        return f"Erro: ficheiro não encontrado: {path}"

    try:
        with open(requested, "r", encoding="utf-8") as fh:
            return fh.read()
    except Exception as exc:
        return f"Erro ao ler ficheiro: {exc}"


# ---------------------------------------------------------------------------
# Ferramenta 3 — Verificador de força de password
# ---------------------------------------------------------------------------

@mcp.tool()
def check_password_strength(password: str) -> dict:
    """
    Analisa a força de uma password com base em critérios comuns.

    Args:
        password: A password a analisar (não é armazenada nem registada).

    Returns:
        Dicionário com critérios individuais e classificação geral
        ("fraca", "média" ou "forte").
    """
    criteria = {
        "comprimento_minimo_8":  len(password) >= 8,
        "comprimento_minimo_12": len(password) >= 12,
        "maiusculas":            bool(re.search(r"[A-Z]", password)),
        "minusculas":            bool(re.search(r"[a-z]", password)),
        "digitos":               bool(re.search(r"\d", password)),
        "caracteres_especiais":  bool(re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', password)),
    }
    score = sum([
        criteria["comprimento_minimo_8"],
        criteria["maiusculas"],
        criteria["minusculas"],
        criteria["digitos"],
        criteria["caracteres_especiais"],
    ])
    if score == 5 and criteria["comprimento_minimo_12"]:
        classification = "forte"
    elif score >= 3:
        classification = "média"
    else:
        classification = "fraca"

    return {**criteria, "classificacao": classification}


# ---------------------------------------------------------------------------
# Ferramenta 4 — Informação do sistema (só leitura)
# ---------------------------------------------------------------------------

@mcp.tool()
def get_system_info() -> dict:
    """
    Devolve informação básica sobre o sistema operativo e Python.

    Returns:
        Dicionário com sistema, versão, arquitectura e versão do Python.
    """
    return {
        "sistema":         platform.system(),
        "versao_os":       platform.version(),
        "arquitectura":    platform.machine(),
        "versao_python":   platform.python_version(),
        "hostname":        platform.node(),
    }


# ---------------------------------------------------------------------------
# Ferramenta 5 — Detector de padrões de prompt injection
# ---------------------------------------------------------------------------

# Padrões comuns de tentativas de prompt injection
_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?prior\s+instructions",
    r"disregard\s+(all\s+)?previous",
    r"forget\s+(all\s+)?previous",
    r"new\s+instructions?:",
    r"system\s*prompt\s*:",
    r"you\s+are\s+now\s+a",
    r"act\s+as\s+(if\s+you\s+are\s+)?a",
    r"pretend\s+(you\s+are|to\s+be)",
    r"jailbreak",
    r"dan\s+mode",
    r"developer\s+mode",
    r"<\s*system\s*>",
    r"\[\s*system\s*\]",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


@mcp.tool()
def scan_text_for_injection(text: str) -> dict:
    """
    Analisa um texto à procura de padrões comuns de prompt injection.

    Útil para sanitizar input do utilizador antes de o passar ao LLM,
    ou para auditar outputs de ferramentas que lêem conteúdo externo.

    Args:
        text: Texto a analisar.

    Returns:
        Dicionário com flag de detecção e lista de padrões encontrados.
    """
    found = []
    for pattern, compiled in zip(_INJECTION_PATTERNS, _COMPILED):
        if compiled.search(text):
            found.append(pattern)

    return {
        "injecao_detectada": len(found) > 0,
        "padroes_encontrados": found,
        "total_padroes": len(found),
        "avaliacao": "SUSPEITO" if found else "OK",
    }


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # stdio transport por defeito — o cliente lança este processo como filho
    mcp.run()
