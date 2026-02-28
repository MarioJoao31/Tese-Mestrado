# MCP + LLM Security Examples

Este projecto demonstra o uso do **Model Context Protocol (MCP)** com um LLM local (Ollama / LM Studio) e explora vulnerabilidades de segurança relevantes para sistemas de agentes com uso de ferramentas.

---

## Estrutura

```
mcp/
├── requirements.txt              # Dependências Python
│
├── 01_basic_mcp/                 # Servidor MCP simples + agente LangChain
│   ├── README.md
│   ├── server.py                 # Servidor MCP com ferramentas básicas
│   └── client.py                 # Agente LangChain via LM Studio/Ollama
│
├── 02_prompt_injection/          # Injeção de prompt directa e indirecta
│   ├── README.md
│   ├── server.py                 # Servidor MCP para os demos
│   ├── direct_injection.py       # Demo de injeção directa
│   └── indirect_injection.py     # Demo de injeção indirecta via ferramenta
│
├── 03_tool_misuse/               # Uso indevido de ferramentas (tool misuse)
│   ├── README.md
│   ├── server.py                 # Servidor MCP com ferramentas "perigosas"
│   └── demo.py                   # Cenários de abuso de ferramentas
│
├── 04_memory_attacks/            # Ataques à memória persistente do agente
│   ├── README.md
│   ├── server.py                 # Servidor MCP com ferramentas de memória
│   └── demo.py                   # Demo de envenenamento de memória
│
└── 05_supply_chain/              # Ataques à cadeia de fornecimento de ferramentas
    ├── README.md
    ├── legitimate_server.py      # Servidor MCP legítimo
    ├── malicious_server.py       # Servidor MCP malicioso (mesma interface)
    └── demo.py                   # Demo do ataque supply chain
```

---

## Pré-requisitos

### 1. Instalar dependências Python
```bash
cd mcp/
pip install -r requirements.txt
```

### 2. Configurar o LLM local

#### Opção A — LM Studio (recomendado)
1. Descarregar [LM Studio](https://lmstudio.ai)
2. Carregar o modelo **Llama 3.1 8B Instruct**
3. Iniciar o servidor local em `http://localhost:1234`

#### Opção B — Ollama
```bash
ollama pull llama3.1:8b
ollama serve   # inicia em http://localhost:11434
```

### 3. Variáveis de ambiente (opcional)
Criar um ficheiro `.env` na pasta `mcp/`:
```env
# LM Studio (padrão)
LLM_BASE_URL=http://localhost:1234/v1
LLM_API_KEY=lm-studio
LLM_MODEL=llama-3.1-8b-instruct

# Ollama (alternativa)
# LLM_BASE_URL=http://localhost:11434/v1
# LLM_API_KEY=ollama
# LLM_MODEL=llama3.1:8b
```

---

## Resumo dos Exemplos

| Pasta | Tema de Segurança | Descrição |
|---|---|---|
| `01_basic_mcp` | — | Introdução ao MCP com LangChain |
| `02_prompt_injection` | Injeção de Prompt | Ataque directo e via output de ferramenta |
| `03_tool_misuse` | Abuso de Ferramentas | Confused-deputy, exfiltração via tool |
| `04_memory_attacks` | Memória | Envenenamento da memória persistente |
| `05_supply_chain` | Supply Chain | Substituição de servidor MCP por um malicioso |

---

## Aviso

> **Estes exemplos têm fins exclusivamente educativos** para investigação de segurança em sistemas de agentes LLM. Não utilizar técnicas demonstradas em sistemas reais sem autorização explícita.
