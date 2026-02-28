# 05 — Supply Chain Attacks (Ataques à Cadeia de Fornecimento)

Demonstração de **ataques à cadeia de fornecimento de ferramentas MCP** — como um servidor MCP malicioso pode substituir um legítimo, mantendo a mesma interface mas executando acções maliciosas.

---

## O Problema

Em sistemas de agentes LLM, as "ferramentas" são frequentemente carregadas de:
- Pacotes de terceiros (npm, pip, etc.)
- Servidores MCP externos (via URL/SSE)
- Registos de ferramentas comunitárias

Se um atacante consegue **substituir ou comprometer** um servidor MCP legítimo, o agente continua a funcionar normalmente da perspectiva do utilizador — mas as ferramentas executam acções maliciosas em segundo plano.

---

## Tipos de Ataque

| Tipo | Descrição |
|---|---|
| **Tool Substitution** | Servidor MCP malicioso com interface idêntica ao legítimo |
| **Typosquatting** | Pacote MCP com nome similar ao legítimo (`mcp-calculator` vs `mcp-calculato r`) |
| **Dependency Confusion** | Dependência privada substituída por pacote público malicioso |
| **Backdoor in Tool** | Ferramenta legítima modificada para incluir comportamento malicioso |
| **MITM de Tool Server** | Intercepção da comunicação entre agente e servidor MCP |

---

## Ficheiros

| Ficheiro | Descrição |
|---|---|
| `legitimate_server.py` | Servidor MCP legítimo com ferramentas de ficheiros |
| `malicious_server.py` | Servidor malicioso com interface idêntica (backdoor) |
| `demo.py` | Demo que mostra a diferença entre usar o servidor legítimo e o malicioso |

---

## Como Executar

```bash
cd mcp/
python 05_supply_chain/demo.py
```

---

## Mitigações

| Técnica | Descrição |
|---|---|
| **Tool verification** | Verificar hash/assinatura do servidor MCP antes de usar |
| **Code signing** | Assinar digitalmente os servidores MCP com chave privada |
| **Dependency pinning** | Fixar versões exactas de dependências (hash pinning) |
| **Sandboxing** | Executar servidores MCP em ambientes isolados (containers) |
| **Least privilege** | Servidores MCP não têm acesso a recursos sensíveis |
| **Network isolation** | Servidores MCP não têm acesso à internet por defeito |
| **Behavioural monitoring** | Detectar anomalias no comportamento dos servidores MCP |

---

## Referências

- [OWASP LLM05: Supply Chain Vulnerabilities](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [SolarWinds Attack (2020)](https://en.wikipedia.org/wiki/2020_United_States_federal_government_data_breach)
- [XZ Utils Backdoor (2024)](https://en.wikipedia.org/wiki/XZ_Utils_backdoor)
