"""
05_supply_chain/demo.py
-----------------------
Demonstração de SUPPLY CHAIN ATTACK em servidores MCP.

O demo mostra:
  1. Comportamento do servidor LEGÍTIMO (referência)
  2. Comportamento do servidor MALICIOSO (idêntico na superfície)
  3. Comparação das acções em background (backdoor vs. sem backdoor)
  4. Técnicas de detecção e mitigação

Uso:
    python 05_supply_chain/demo.py
"""

import asyncio
import sys
import os
import json
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


# ---------------------------------------------------------------------------
# Utilitário
# ---------------------------------------------------------------------------

async def call_tool(session: ClientSession, tool_name: str, params: dict) -> str:
    """Chama uma ferramenta MCP e devolve o resultado."""
    result = await session.call_tool(tool_name, params)
    if result.content:
        return result.content[0].text
    return "(sem resultado)"


async def run_scenario(server_script: str, label: str) -> dict:
    """
    Executa um conjunto de operações num servidor MCP e devolve os resultados.
    Retorna um dicionário com os resultados de cada operação.
    """
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[server_script],
    )

    results = {}
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Verificar a identidade do servidor
            tools_list = await session.list_tools()
            results["server_name"] = label
            results["tools"] = [t.name for t in tools_list.tools]

            # Operação 1: Escrever um ficheiro com dados "sensíveis"
            r = await call_tool(session, "file_write", {
                "filename": "config.json",
                "content": json.dumps({
                    "api_key": "prod-api-key-super-secret",
                    "db_host": "db.internal.corp.example",
                    "db_pass": "db-password-confidential",
                }),
            })
            results["write_result"] = r

            # Operação 2: Ler o ficheiro escrito
            r = await call_tool(session, "file_read", {"filename": "config.json"})
            results["read_result"] = r[:80] + "..."

            # Operação 3: Listar ficheiros
            r = await call_tool(session, "file_list", {})
            results["list_result"] = r

            # Operação 4: Calcular hash
            r = await call_tool(session, "file_hash", {"filename": "config.json"})
            results["hash_result"] = r

    return results


# ---------------------------------------------------------------------------
# Verificação de integridade do servidor (mitigação)
# ---------------------------------------------------------------------------

def compute_server_hash(server_script: str) -> str:
    """
    Calcula o hash SHA-256 do ficheiro do servidor MCP.
    Útil para verificar a integridade antes de usar o servidor.
    """
    sha256 = hashlib.sha256()
    with open(server_script, "rb") as fh:
        for chunk in iter(lambda: fh.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_server_integrity(server_script: str, expected_hash: str) -> bool:
    """Verifica se o hash do servidor corresponde ao esperado."""
    actual_hash = compute_server_hash(server_script)
    return actual_hash == expected_hash


# ---------------------------------------------------------------------------
# Demo principal
# ---------------------------------------------------------------------------

async def main() -> None:
    script_dir = os.path.dirname(__file__)
    legit_server   = os.path.join(script_dir, "legitimate_server.py")
    malicious_server = os.path.join(script_dir, "malicious_server.py")
    exfil_log      = os.path.join(script_dir, "exfil_simulation.log")

    print("=" * 70)
    print("DEMO: SUPPLY CHAIN ATTACK — Substituição de Servidor MCP")
    print("=" * 70)

    # -----------------------------------------------------------------------
    # Parte 1: Calcular hashes de referência (estado limpo)
    # -----------------------------------------------------------------------
    print("\n[1] Verificação de Integridade dos Servidores")
    print("─" * 60)

    legit_hash    = compute_server_hash(legit_server)
    malicious_hash = compute_server_hash(malicious_server)

    print(f"  Hash servidor legítimo:   {legit_hash[:32]}...")
    print(f"  Hash servidor malicioso:  {malicious_hash[:32]}...")
    print(f"  Hashes iguais? {legit_hash == malicious_hash}")
    print(
        "  → Se o programador armazenar o hash do servidor legítimo,\n"
        "    pode detectar substituições antes de executar."
    )

    # -----------------------------------------------------------------------
    # Parte 2: Usar o servidor legítimo
    # -----------------------------------------------------------------------
    print("\n[2] Servidor LEGÍTIMO — comportamento normal")
    print("─" * 60)

    legit_results = await run_scenario(legit_server, "Legítimo")
    print(f"  Ferramentas: {legit_results['tools']}")
    print(f"  Resultado de write: {legit_results['write_result']}")
    print(f"  Resultado de read:  {legit_results['read_result']}")
    print(f"  Hash do ficheiro:   {legit_results['hash_result'][:32]}...")

    # Verificar se existe log de exfiltração (não deve existir)
    legit_exfil_exists = os.path.exists(exfil_log)
    print(f"  Log de exfiltração criado? {legit_exfil_exists}")
    if not legit_exfil_exists:
        print("  ✅ Nenhuma exfiltração detectada — servidor legítimo")

    # -----------------------------------------------------------------------
    # Parte 3: Usar o servidor malicioso (mesma interface)
    # -----------------------------------------------------------------------
    print("\n[3] Servidor MALICIOSO — interface idêntica, backdoor activo")
    print("─" * 60)
    print("  ⚠️  O atacante substituiu o servidor MCP pelo malicioso.")
    print("  O agente não detecta qualquer diferença na interface.\n")

    # Remover log anterior se existir
    if os.path.exists(exfil_log):
        os.remove(exfil_log)

    malicious_results = await run_scenario(malicious_server, "Malicioso")
    print(f"  Ferramentas: {malicious_results['tools']}")
    print(f"  Resultado de write: {malicious_results['write_result']}")
    print(f"  Resultado de read:  {malicious_results['read_result']}")
    print(f"  Hash do ficheiro:   {malicious_results['hash_result'][:32]}...")

    # -----------------------------------------------------------------------
    # Parte 4: Mostrar o backdoor em acção
    # -----------------------------------------------------------------------
    print("\n[4] Backdoor em Acção — O que o servidor malicioso fez em background")
    print("─" * 60)

    if os.path.exists(exfil_log):
        print("  ⚠️  Log de exfiltração CRIADO pelo servidor malicioso!")
        print("  Dados que seriam exfiltrados:\n")
        with open(exfil_log, "r") as fh:
            for line in fh:
                try:
                    entry = json.loads(line.strip())
                    print(f"  [{entry['timestamp']}] {entry['action']} '{entry['filename']}'")
                    print(f"    Preview: {entry['data_preview'][:100]}")
                    print(f"    Nota: {entry['note']}")
                except json.JSONDecodeError:
                    print(f"  {line.strip()}")
        # Remover log após mostrar
        os.remove(exfil_log)
    else:
        print("  (Nenhum log de exfiltração encontrado)")

    # -----------------------------------------------------------------------
    # Parte 5: Comparação de resultados visíveis
    # -----------------------------------------------------------------------
    print("\n[5] Comparação — O agente não detecta diferença na interface")
    print("─" * 60)

    comparisons = [
        ("Ferramentas",  legit_results["tools"],        malicious_results["tools"]),
        ("Write result", legit_results["write_result"], malicious_results["write_result"]),
        ("Hash ficheiro",legit_results["hash_result"],  malicious_results["hash_result"]),
    ]

    for label, legit_val, mal_val in comparisons:
        same = str(legit_val) == str(mal_val)
        icon = "✅ Idêntico" if same else "⚠️  Diferente"
        print(f"  {label}: {icon}")

    print(
        "\n  Conclusão: Os resultados visíveis são idênticos.\n"
        "  O agente (e o utilizador) não detectam o ataque apenas pela interface."
    )

    # -----------------------------------------------------------------------
    # Parte 6: Mitigações
    # -----------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("MITIGAÇÕES PARA SUPPLY CHAIN ATTACKS")
    print("=" * 70)

    print("\n  1. Hash pinning — verificar o hash do servidor antes de usar:")
    print(f"     Hash esperado (legítimo): {legit_hash}")
    print(f"     Hash actual (malicioso):  {malicious_hash}")
    print(f"     Corresponde? {verify_server_integrity(malicious_server, legit_hash)}")
    print("     → Com hash pinning, o servidor malicioso seria REJEITADO\n")

    mitigacoes = [
        "2. Code signing — assinar servidores MCP com chave privada (verificar assinatura)",
        "3. Dependency pinning — fixar versões exactas no requirements.txt com hashes",
        "4. Sandboxing — executar servidores MCP em containers sem acesso à rede",
        "5. Least privilege — servidores MCP não têm acesso a credenciais ou rede",
        "6. Behavioural monitoring — detectar chamadas de rede não esperadas",
        "7. Supply chain audit — auditar regularmente as dependências com ferramentas como 'pip-audit'",
        "8. Reproducible builds — verificar que o binário corresponde ao código fonte",
    ]
    for m in mitigacoes:
        print(f"  {m}")


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    asyncio.run(main())
