# 03 — Tool Misuse (Abuso de Ferramentas)

Demonstração de cenários em que um agente LLM utiliza ferramentas de forma incorrecta, não intencional ou maliciosa — seja por manipulação do utilizador ou por limitações intrínsecas do LLM.

---

## O que é Tool Misuse?

Tool misuse ocorre quando um agente LLM usa as ferramentas que lhe foram atribuídas de formas não previstas ou indesejadas pelo programador/operador. Isto pode acontecer por:

1. **Manipulação directa** — o utilizador convence o agente a usar uma ferramenta perigosa  
2. **Confused Deputy** — o agente age em nome do atacante usando as suas próprias permissões  
3. **Privilege Escalation** — o agente usa ferramentas em combinação para obter capacidades não autorizadas  
4. **Data Exfiltration via Tool** — o agente usa uma ferramenta legítima para exfiltrar dados sensíveis  
5. **TOCTOU (Time of Check to Time of Use)** — condições de corrida entre validação e uso  

---

## Ficheiros

| Ficheiro | Descrição |
|---|---|
| `server.py` | Servidor MCP com ferramentas "poderosas" (ficheiros, email, shell simulado) |
| `demo.py` | Demonstração de 4 cenários de tool misuse + mitigações |

---

## Como Executar

```bash
cd mcp/
python 03_tool_misuse/demo.py
```

---

## Ferramentas no Servidor

| Ferramenta | Permissão | Risco |
|---|---|---|
| `write_file` | Escreve ficheiros em `./workspace/` | Path traversal, overwrite de ficheiros críticos |
| `send_notification` | Envia notificações (simulado) | Exfiltração de dados |
| `run_query` | Executa queries SQL (simulado) | SQL injection, acesso não autorizado |
| `list_users` | Lista utilizadores do sistema | Reconhecimento de alvos |
| `get_secret` | Obtém segredos por chave | Acesso não autorizado a credenciais |

---

## Mitigações

| Técnica | Descrição |
|---|---|
| **Principle of Least Privilege** | Cada agente tem acesso apenas às ferramentas necessárias |
| **Tool Access Control** | Listas de controlo de acesso por utilizador/contexto |
| **Human-in-the-Loop** | Acções críticas requerem aprovação humana |
| **Audit Logging** | Todas as chamadas a ferramentas são registadas |
| **Input/Output Validation** | Validação de parâmetros antes e depois da chamada |
| **Rate Limiting** | Limite de chamadas por ferramenta por sessão |

---

## Referências

- [OWASP Top 10 for LLM — LLM06: Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Confused Deputy Problem](https://en.wikipedia.org/wiki/Confused_deputy_problem)
