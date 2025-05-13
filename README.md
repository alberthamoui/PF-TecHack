# 🛡️ PF-TecHack — Ferramenta de Detecção de Phishing

Projeto final da disciplina **Tecnologias Hacker (2025/1)**, com foco em **análise heurística de URLs** e **detecção de sites de phishing** por meio de critérios técnicos e visuais.

## Objetivo

Desenvolver uma aplicação web que permita:
- Inserir e analisar URLs suspeitas;
- Detectar características comuns em tentativas de phishing;
- Registrar e visualizar o histórico de análises;
- Fornecer feedback visual e explicações sobre os riscos detectados.

---

## Como executar

### 1. Instale as dependências:

```bash
pip install -r requirements.txt
```

### 2. Execute a aplicação:

```bash
python src/app.py
```

### 3. Acesse no navegador:

```
http://localhost:5000
```

---

## Funcionalidades Implementadas

* [x] Análise de URL com base em heurísticas simples:
  * Substituição de letras por números
  * Uso excessivo de subdomínios
  * Presença de caracteres especiais
* [x] Consultas WHOIS para verificar idade do domínio
* [x] Verificação de certificados SSL (validez, emissor)
* [x] Análise de DNS (resolução válida, uso de DNS dinâmico)
* [x] Similaridade com domínios legítimos (distância de Levenshtein)
* [x] Análise de conteúdo HTML (formulários de login, dados sensíveis)
* [x] Interface web com visualização dos resultados
* [x] Histórico de análises salvas em `logs.csv`
* [x] Gráfico automático da distribuição de alertas

---

## 🧠 Descrição Técnica

### O sistema foi desenvolvido com:

* **Flask:** (framework web)
* **BeautifulSoup:** para análise de conteúdo HTML
* **fuzzywuzzy:** para verificação de similaridade com domínios legítimos
* **whois**, **dns.resolver**, **ssl**, **socket:** para metadados técnicos
* **Matplotlib:** para geração de gráficos
* **CSV:** como banco de dados leve para histórico

### Arquitetura modular com scripts separados:

* `app.py`: servidor Flask e rotas
* `analyzer.py`: verificações heurísticas e técnicas
* `graficos.py`: geração do gráfico de alertas
* `templates/`: HTML da interface web

---

## 🗂️ Estrutura dos Arquivos

```
PF-TecHack/
│
├── src/
│   ├── app.py               # Lógica principal Flask
│   ├── analyzer.py          # Funções de verificação de URLs
│   ├── graficos.py          # Geração de gráfico com Matplotlib
│   ├── utils.py             # Funções auxiliares (futuro)
│   └── templates/
│       ├── index.html       # Página principal
│       └── historico.html   # Histórico e gráfico
│
├── logs.csv                 # Histórico salvo de análises
├── requirements.txt         # Pacotes necessários
└── README.md                # Documentação
```

---

## 👨‍💻 Autor

**Albert D. Hamoui**
Insper — Tecnologias Hacker 2025/1

---

## 📝 Licença

Uso acadêmico apenas. Proibido uso em produção sem ajustes de segurança e privacidade.
