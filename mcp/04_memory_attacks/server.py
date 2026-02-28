"""
04_memory_attacks/server.py
----------------------------
Servidor MCP com ferramentas de memória persistente.

A memória é guardada num ficheiro JSON local (memory.json) para simular
persistência entre sessões — como uma base de dados vectorial simplificada.

Ferramentas:
  - memory_write  : Escreve uma entrada na memória
  - memory_read   : Lê entradas da memória por chave ou todas
  - memory_search : Pesquisa entradas por conteúdo
  - memory_delete : Apaga uma entrada da memória
  - memory_clear  : Limpa toda a memória (reset)
  - memory_audit  : Mostra o audit log de escritas
"""

import json
import os
import re
import datetime
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Memory Demo Server")

# ---------------------------------------------------------------------------
# Persistência em ficheiro JSON
# ---------------------------------------------------------------------------

_MEMORY_FILE = os.path.join(os.path.dirname(__file__), "memory.json")
_AUDIT_FILE  = os.path.join(os.path.dirname(__file__), "memory_audit.json")

# Chaves reservadas que nunca podem ser sobrescritas pelo utilizador
_READONLY_KEYS = {
    "system.identity",
    "system.instructions",
    "system.security_policy",
    "system.admin_password",
}


def _load_memory() -> dict:
    """Carrega a memória do ficheiro, ou devolve um dicionário vazio."""
    if os.path.exists(_MEMORY_FILE):
        try:
            with open(_MEMORY_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_memory(memory: dict) -> None:
    """Guarda a memória no ficheiro."""
    with open(_MEMORY_FILE, "w", encoding="utf-8") as fh:
        json.dump(memory, fh, ensure_ascii=False, indent=2)


def _load_audit() -> list:
    """Carrega o audit log."""
    if os.path.exists(_AUDIT_FILE):
        try:
            with open(_AUDIT_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _append_audit(action: str, key: str, value_preview: str, blocked: bool = False) -> None:
    """Acrescenta uma entrada ao audit log."""
    audit = _load_audit()
    audit.append({
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "action": action,
        "key": key,
        "value_preview": value_preview[:80],
        "blocked": blocked,
    })
    with open(_AUDIT_FILE, "w", encoding="utf-8") as fh:
        json.dump(audit, fh, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Ferramenta 1 — Escrever na memória
# ---------------------------------------------------------------------------

@mcp.tool()
def memory_write(key: str, value: str, source: str = "user") -> str:
    """
    Escreve (ou actualiza) uma entrada na memória persistente do agente.

    Versão segura:
      - Bloqueia escrita em chaves do sistema (readonly_keys)
      - Regista a origem (source) para auditoria
      - Detecta tentativas de injeção no valor

    Args:
        key:    Chave identificadora da memória (e.g. "user.preferencias").
        value:  Valor a armazenar.
        source: Origem da escrita: "user", "tool", "system" (default: "user").

    Returns:
        Confirmação ou mensagem de erro.
    """
    # Validação da chave
    if not re.match(r"^[a-zA-Z0-9_\.\-]{1,100}$", key):
        _append_audit("write", key, value, blocked=True)
        return "Erro: chave inválida. Use apenas letras, números, '.', '_', '-' (máx. 100 chars)."

    # Protecção de chaves do sistema
    if key in _READONLY_KEYS:
        _append_audit("write", key, value, blocked=True)
        return f"Erro: a chave '{key}' é reservada pelo sistema e não pode ser modificada."

    # Detecção de injeção no valor (para memória não originada no sistema)
    if source != "system":
        injection_patterns = [
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"you\s+are\s+now\s+a",
            r"new\s+prime\s+directive",
            r"forget\s+(everything|all)",
            r"\[\s*system\s*[:\]]",
        ]
        for pattern in injection_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                _append_audit("write", key, value, blocked=True)
                return (
                    "Erro: o valor contém padrões de prompt injection "
                    "e foi rejeitado. Evento registado para auditoria."
                )

    memory = _load_memory()
    memory[key] = {
        "value":     value,
        "source":    source,
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }
    _save_memory(memory)
    _append_audit("write", key, value)
    return f"Memória actualizada: '{key}' = '{value[:50]}{'...' if len(value) > 50 else ''}'"


# ---------------------------------------------------------------------------
# Ferramenta 2 — Ler da memória
# ---------------------------------------------------------------------------

@mcp.tool()
def memory_read(key: str = "") -> str:
    """
    Lê entradas da memória persistente.

    Args:
        key: Chave específica a ler. Se vazio, devolve todas as entradas.

    Returns:
        Conteúdo da memória em formato JSON.
    """
    memory = _load_memory()

    if key:
        if key not in memory:
            return f"Memória vazia para a chave '{key}'."
        entry = memory[key]
        return json.dumps({key: entry}, ensure_ascii=False, indent=2)

    if not memory:
        return "A memória está vazia."
    return json.dumps(memory, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Ferramenta 3 — Pesquisar na memória
# ---------------------------------------------------------------------------

@mcp.tool()
def memory_search(query: str) -> str:
    """
    Pesquisa entradas na memória cujo valor contenha o texto especificado.

    Args:
        query: Texto a pesquisar nos valores da memória.

    Returns:
        Entradas correspondentes em formato JSON.
    """
    memory = _load_memory()
    results = {
        k: v for k, v in memory.items()
        if query.lower() in v.get("value", "").lower()
    }
    if not results:
        return f"Nenhuma entrada encontrada para '{query}'."
    return json.dumps(results, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Ferramenta 4 — Apagar entrada
# ---------------------------------------------------------------------------

@mcp.tool()
def memory_delete(key: str) -> str:
    """
    Apaga uma entrada da memória persistente.

    Não é possível apagar chaves do sistema.

    Args:
        key: Chave a apagar.

    Returns:
        Confirmação ou mensagem de erro.
    """
    if key in _READONLY_KEYS:
        return f"Erro: a chave '{key}' é reservada e não pode ser apagada."

    memory = _load_memory()
    if key not in memory:
        return f"Chave '{key}' não encontrada na memória."

    del memory[key]
    _save_memory(memory)
    _append_audit("delete", key, "")
    return f"Entrada '{key}' apagada da memória."


# ---------------------------------------------------------------------------
# Ferramenta 5 — Limpar memória (reset)
# ---------------------------------------------------------------------------

@mcp.tool()
def memory_clear(confirm: str = "") -> str:
    """
    Limpa toda a memória persistente do agente.

    Para confirmar, passar confirm="SIM_APAGAR_TUDO".
    Requer confirmação explícita para prevenir limpeza acidental.

    Args:
        confirm: Deve ser "SIM_APAGAR_TUDO" para executar.

    Returns:
        Confirmação ou instrução de confirmação.
    """
    if confirm != "SIM_APAGAR_TUDO":
        return (
            "Para limpar toda a memória, chama novamente com confirm='SIM_APAGAR_TUDO'. "
            "Esta acção é irreversível."
        )

    memory = _load_memory()
    count = len(memory)
    _save_memory({})
    _append_audit("clear", "*", f"Apagadas {count} entradas")
    return f"Memória limpa: {count} entradas apagadas."


# ---------------------------------------------------------------------------
# Ferramenta 6 — Audit log
# ---------------------------------------------------------------------------

@mcp.tool()
def memory_audit() -> str:
    """
    Devolve o audit log de todas as operações de memória.

    Returns:
        Audit log em formato JSON.
    """
    audit = _load_audit()
    if not audit:
        return "Audit log vazio."
    return json.dumps(audit, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
