"""
03_tool_misuse/server.py
------------------------
Servidor MCP com ferramentas "poderosas" para demonstrar cenários de tool misuse.

As ferramentas simulam operações típicas de um agente empresarial:
  - Escrita de ficheiros
  - Envio de notificações
  - Execução de queries à base de dados
  - Acesso a segredos/credenciais

Cada ferramenta tem versões vulnerável e segura comentadas para fins didácticos.
"""

import os
import re
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Tool Misuse Demo Server")

# ---------------------------------------------------------------------------
# Contexto simulado
# ---------------------------------------------------------------------------

# Utilizadores fictícios (simula uma base de dados de utilizadores)
_USERS = [
    {"id": 1, "nome": "Alice Admin",  "role": "admin",  "email": "alice@corp.example"},
    {"id": 2, "nome": "Bob Developer","role": "dev",    "email": "bob@corp.example"},
    {"id": 3, "nome": "Carlos HR",    "role": "hr",     "email": "carlos@corp.example"},
    {"id": 4, "nome": "Diana Finance","role": "finance","email": "diana@corp.example"},
]

# Segredos fictícios (simula um gestor de segredos)
_SECRETS = {
    "DB_PASSWORD":    "s3cr3t_db_pass",
    "API_KEY_PROD":   "prod-api-key-xyz-123",
    "JWT_SECRET":     "jwt-signing-key-abc",
    "INTERNAL_TOKEN": "internal-service-token",
}

# Log de acções (simula auditoria)
_AUDIT_LOG: list[dict] = []


def _log_action(tool: str, params: dict, result: str, blocked: bool = False) -> None:
    """Regista uma acção no log de auditoria."""
    import datetime
    _AUDIT_LOG.append({
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "tool": tool,
        "params": params,
        "result_preview": str(result)[:100],
        "blocked": blocked,
    })


# ---------------------------------------------------------------------------
# Ferramenta 1 — Escrita de ficheiros
# ---------------------------------------------------------------------------

@mcp.tool()
def write_file(filename: str, content: str) -> str:
    """
    Escreve conteúdo num ficheiro dentro de ./workspace/.

    Versão segura: valida o caminho para evitar path traversal.

    Args:
        filename: Nome do ficheiro (relativo a ./workspace/).
        content:  Conteúdo a escrever.

    Returns:
        Confirmação ou mensagem de erro.
    """
    workspace = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "workspace")
    )
    os.makedirs(workspace, exist_ok=True)

    requested = os.path.abspath(os.path.join(workspace, filename))

    # Protecção contra path traversal
    if not requested.startswith(workspace + os.sep) and requested != workspace:
        _log_action("write_file", {"filename": filename}, "BLOQUEADO: path traversal", blocked=True)
        return "Erro: acesso negado — o caminho tem de estar dentro de ./workspace/."

    # Protecção: não permite sobrescrever ficheiros do sistema
    blocked_names = {"server.py", "demo.py", "requirements.txt", ".env"}
    if os.path.basename(requested) in blocked_names:
        _log_action("write_file", {"filename": filename}, "BLOQUEADO: ficheiro protegido", blocked=True)
        return f"Erro: não é permitido sobrescrever o ficheiro '{filename}'."

    try:
        with open(requested, "w", encoding="utf-8") as fh:
            fh.write(content)
        _log_action("write_file", {"filename": filename}, f"OK: {len(content)} bytes escritos")
        return f"Ficheiro '{filename}' escrito com sucesso ({len(content)} bytes)."
    except Exception as exc:
        return f"Erro ao escrever ficheiro: {exc}"


# ---------------------------------------------------------------------------
# Ferramenta 2 — Envio de notificações
# ---------------------------------------------------------------------------

# Domínios de email autorizados (whitelist)
_ALLOWED_EMAIL_DOMAINS = {"corp.example", "admin.example"}


@mcp.tool()
def send_notification(recipient_email: str, subject: str, body: str) -> str:
    """
    [SIMULAÇÃO] Envia uma notificação por email.

    Versão segura: valida o destinatário contra uma whitelist de domínios.
    Sem whitelist, esta ferramenta pode ser usada para exfiltrar dados.

    Args:
        recipient_email: Email do destinatário.
        subject:         Assunto da notificação.
        body:            Corpo da mensagem.

    Returns:
        Confirmação ou mensagem de erro.
    """
    # Validação básica de formato de email
    if not re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", recipient_email):
        _log_action("send_notification", {"recipient": recipient_email}, "BLOQUEADO: email inválido", blocked=True)
        return "Erro: endereço de email inválido."

    # Validação de domínio (whitelist)
    domain = recipient_email.split("@")[-1].lower()
    if domain not in _ALLOWED_EMAIL_DOMAINS:
        _log_action(
            "send_notification",
            {"recipient": recipient_email},
            "BLOQUEADO: domínio não autorizado",
            blocked=True,
        )
        return (
            f"Erro: o domínio '{domain}' não está na lista de destinatários autorizados. "
            f"Domínios permitidos: {', '.join(_ALLOWED_EMAIL_DOMAINS)}"
        )

    _log_action("send_notification", {"recipient": recipient_email, "subject": subject}, "OK: enviado (simulação)")
    return f"[SIMULAÇÃO] Notificação enviada para {recipient_email} com assunto '{subject}'."


# ---------------------------------------------------------------------------
# Ferramenta 3 — Queries SQL (simulação)
# ---------------------------------------------------------------------------

# Base de dados simulada (apenas leitura para este demo)
_DB_TABLES = {
    "products": [
        {"id": 1, "name": "Widget A", "price": 9.99,  "stock": 100},
        {"id": 2, "name": "Widget B", "price": 19.99, "stock": 50},
    ],
    "orders": [
        {"id": 1, "customer_id": 42, "product_id": 1, "quantity": 5},
        {"id": 2, "customer_id": 99, "product_id": 2, "quantity": 2},
    ],
}

# Tabelas permitidas para consulta
_ALLOWED_TABLES = {"products", "orders"}


@mcp.tool()
def run_query(table: str, filter_field: str = "", filter_value: str = "") -> str:
    """
    [SIMULAÇÃO] Executa uma consulta simples à base de dados.

    Versão segura: usa parâmetros em vez de SQL directo (evita SQL injection).
    Apenas permite consultas às tabelas autorizadas.

    Args:
        table:        Nome da tabela a consultar.
        filter_field: Campo pelo qual filtrar (opcional).
        filter_value: Valor do filtro (opcional).

    Returns:
        Resultados em formato texto, ou mensagem de erro.
    """
    import json

    # Whitelist de tabelas
    if table not in _ALLOWED_TABLES:
        _log_action("run_query", {"table": table}, "BLOQUEADO: tabela não autorizada", blocked=True)
        return (
            f"Erro: tabela '{table}' não autorizada. "
            f"Tabelas disponíveis: {', '.join(_ALLOWED_TABLES)}"
        )

    # Validação de nomes de campo (apenas alfanumérico + underscore)
    if filter_field and not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", filter_field):
        _log_action("run_query", {"table": table, "field": filter_field}, "BLOQUEADO: field inválido", blocked=True)
        return "Erro: nome de campo inválido."

    rows = _DB_TABLES[table]

    # Aplicar filtro se fornecido
    if filter_field and filter_value:
        rows = [
            row for row in rows
            if str(row.get(filter_field, "")).lower() == filter_value.lower()
        ]

    _log_action("run_query", {"table": table}, f"OK: {len(rows)} rows")
    return json.dumps(rows, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Ferramenta 4 — Lista de utilizadores
# ---------------------------------------------------------------------------

@mcp.tool()
def list_users(role_filter: str = "") -> str:
    """
    Lista utilizadores do sistema (sem passwords ou dados sensíveis).

    Args:
        role_filter: Filtrar por role (opcional). Valores: admin, dev, hr, finance.

    Returns:
        Lista de utilizadores em formato texto.
    """
    import json

    users = _USERS
    if role_filter:
        users = [u for u in users if u["role"].lower() == role_filter.lower()]

    # Não retorna campos sensíveis (apenas id, nome, role)
    safe_users = [{"id": u["id"], "nome": u["nome"], "role": u["role"]} for u in users]
    _log_action("list_users", {"role_filter": role_filter}, f"OK: {len(safe_users)} users")
    return json.dumps(safe_users, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Ferramenta 5 — Acesso a segredos (com controlo de acesso simulado)
# ---------------------------------------------------------------------------

# Segredos acessíveis apenas com token de serviço
_REQUIRED_SERVICE_TOKEN = "service-token-demo-123"


@mcp.tool()
def get_secret(secret_key: str, service_token: str) -> str:
    """
    Obtém um segredo do gestor de credenciais.

    Requer um token de serviço válido para aceder — demonstra que
    ferramentas sensíveis devem ter autenticação própria.

    Args:
        secret_key:    Chave do segredo (e.g. "DB_PASSWORD").
        service_token: Token de autenticação do serviço.

    Returns:
        Valor do segredo, ou mensagem de erro.
    """
    # Validação do token de serviço
    if service_token != _REQUIRED_SERVICE_TOKEN:
        _log_action(
            "get_secret",
            {"key": secret_key},
            "BLOQUEADO: token inválido",
            blocked=True,
        )
        return "Erro: token de serviço inválido ou ausente."

    if secret_key not in _SECRETS:
        return f"Erro: segredo '{secret_key}' não encontrado."

    _log_action("get_secret", {"key": secret_key}, "OK: segredo acedido")
    # Em produção, o segredo seria injectado via variável de ambiente, não devolvido em texto limpo
    return f"[SIMULAÇÃO] Segredo '{secret_key}' = {_SECRETS[secret_key]}"


# ---------------------------------------------------------------------------
# Ferramenta de auditoria
# ---------------------------------------------------------------------------

@mcp.tool()
def get_audit_log() -> str:
    """
    Devolve o log de auditoria de todas as chamadas a ferramentas nesta sessão.

    Returns:
        Log em formato JSON.
    """
    import json
    return json.dumps(_AUDIT_LOG, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
