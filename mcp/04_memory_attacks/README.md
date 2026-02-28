# 04 — Memory Attacks (Ataques à Memória do Agente)

Demonstração de **ataques à memória persistente** de um agente LLM — como um atacante pode envenenar o contexto de sessões futuras através das ferramentas de memória.

---

## O Problema

Agentes LLM modernos frequentemente usam mecanismos de memória para manter contexto entre sessões:

- **Short-term memory**: contexto da conversa actual
- **Long-term memory**: informação persistida entre sessões (ficheiros, bases de dados, vectorstores)
- **Tool memory**: resultados de ferramentas cacheados e reutilizados

Se um atacante consegue **escrever na memória do agente** — directamente ou via prompt injection — pode:

1. **Alterar o comportamento do agente** em todas as sessões futuras
2. **Injectar factos falsos** que o agente usará como contexto confiável
3. **Esconder instruções persistentes** que sobrevivem a novas sessões
4. **Contaminar o histórico** de forma que os utilizadores futuros sejam afectados

---

## Ficheiros

| Ficheiro | Descrição |
|---|---|
| `server.py` | Servidor MCP com ferramentas de memória persistente |
| `demo.py` | Demonstração de cenários de envenenamento de memória + mitigações |

---

## Como Executar

```bash
cd mcp/
python 04_memory_attacks/demo.py
```

**Nota**: O servidor cria um ficheiro `memory.json` na pasta `04_memory_attacks/` para persistência entre execuções. Apaga este ficheiro para "limpar" a memória.

---

## Cenários Demonstrados

| Cenário | Descrição |
|---|---|
| **Memory Poisoning** | Atacante escreve factos falsos na memória persistente |
| **Persistent Instruction Injection** | Instruções maliciosas que sobrevivem entre sessões |
| **Cross-Session Contamination** | Utilizador A envenena a memória, afecta Utilizador B |
| **Memory Exfiltration** | Atacante lê toda a memória do agente |

---

## Mitigações

| Técnica | Descrição |
|---|---|
| **Memory isolation** | Memória separada por utilizador/sessão |
| **Source attribution** | Cada entrada na memória tem metadados de origem |
| **Memory expiry** | Entradas antigas são eliminadas automaticamente |
| **Write validation** | Apenas conteúdo validado pode ser escrito na memória |
| **Read-only system facts** | Factos do sistema nunca podem ser sobrescritos pelo utilizador |
| **Memory audit** | Log de todas as escritas na memória |

---

## Referências

- [OWASP LLM07: Insecure Plugin Design](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Poisoning Language Model Memories (Wallace et al.)](https://arxiv.org/abs/2310.02030)
