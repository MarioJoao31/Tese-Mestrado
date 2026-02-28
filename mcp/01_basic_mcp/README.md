# 01 — MCP Básico com LangChain e LM Studio

Exemplo introdutório de um **servidor MCP** e de um **agente LangChain** que usa o servidor via LM Studio (ou Ollama).

---

## Ficheiros

| Ficheiro | Descrição |
|---|---|
| `server.py` | Servidor MCP com ferramentas de segurança básicas |
| `client.py` | Agente LangChain que usa as ferramentas do servidor |

---

## Como Executar

### Passo 1 — Iniciar o LLM

Garantir que o LM Studio ou Ollama está a correr com o modelo Llama 3.1 8B.

### Passo 2 — Executar o cliente

O cliente inicia o servidor MCP automaticamente como subprocesso:

```bash
cd mcp/
python 01_basic_mcp/client.py
```

O servidor **não precisa de ser iniciado manualmente** — o cliente usa *stdio transport* e lança o servidor como processo filho.

---

## Ferramentas Disponíveis no Servidor

| Ferramenta | Descrição |
|---|---|
| `calculate` | Avalia expressões matemáticas simples (com whitelist de caracteres) |
| `read_file` | Lê ficheiros dentro da pasta `./data/` (proteção contra path traversal) |
| `check_password_strength` | Verifica a força de uma password |
| `get_system_info` | Devolve informação básica do sistema (só leitura) |
| `scan_text_for_injection` | Detecta padrões de prompt injection num texto |

---

## Arquitectura

```
client.py  ──stdio──>  server.py
    │                      │
LangChain               FastMCP
  Agent                 (tools)
    │
LM Studio / Ollama
(Llama 3.1 8B)
```

O protocolo MCP usa *JSON-RPC over stdio* por defeito, pelo que não é necessária qualquer configuração de rede para a comunicação cliente-servidor.
