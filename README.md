# 🔍 Detector de Padrões Suspeitos - SOC Blue Team

(Still in development)
Um sistema automatizado de detecção de ameaças para análise de logs em ambientes SOC (Security Operations Center), desenvolvido para equipes de Blue Team.

## 📋 Índice

- [Sobre](#sobre)
- [Funcionalidades](#funcionalidades)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Uso](#uso)
- [Detecções Implementadas](#detecções-implementadas)
- [Formato dos Logs](#formato-dos-logs)
- [Exemplos](#exemplos)
- [Personalização](#personalização)
- [Contribuição](#contribuição)
- [Licença](#licença)

## 🎯 Sobre

O Detector de Padrões Suspeitos é uma ferramenta Python projetada para automatizar a identificação de atividades maliciosas em logs de eventos do Windows. Desenvolvido especificamente para analistas de SOC, o sistema detecta múltiplos tipos de ameaças e gera relatórios detalhados com classificação de severidade.

## ⚡ Funcionalidades

- **Detecção Automatizada**: Identifica 6 tipos diferentes de padrões suspeitos
- **Configuração Flexível**: Parâmetros ajustáveis via arquivo JSON
- **Logging Completo**: Registra todas as atividades e erros
- **Exportação de Resultados**: Gera relatórios em formato JSON
- **Classificação de Severidade**: Eventos categorizados como Low, Medium ou High
- **Tratamento Robusto de Erros**: Processa logs mesmo com entradas malformadas

## 🚀 Instalação

### Pré-requisitos

- Python 3.7+
- pip (gerenciador de pacotes Python)

### Dependências

```bash
pip install pandas numpy
```

### Download

```bash
git clone https://github.com/seu-usuario/suspicious-pattern-detector.git
cd suspicious-pattern-detector
```

## ⚙️ Configuração

### Configuração Padrão

O detector vem com configurações pré-definidas que podem ser ajustadas:

```python
{
    'failed_login_threshold': 5,           # Número mínimo de tentativas falhadas
    'failed_login_window_minutes': 10,     # Janela de tempo (minutos)
    'brute_force_threshold': 10,           # Threshold para força bruta
    'brute_force_window_minutes': 30,      # Janela para força bruta
    'off_hours_start': 22,                 # Início horário não comercial
    'off_hours_end': 6,                    # Fim horário não comercial
    'suspicious_processes': [...],         # Lista de processos suspeitos
    'admin_accounts': [...],               # Contas administrativas
    'critical_systems': [...]              # Sistemas críticos
}
```

### Arquivo de Configuração Personalizado

Crie um arquivo `config.json`:

```json
{
    "failed_login_threshold": 3,
    "brute_force_threshold": 15,
    "admin_accounts": ["administrator", "admin", "root", "sysadmin"],
    "critical_systems": ["dc01", "exchange01", "fileserver01", "backup01"]
}
```

## 🔧 Uso

### Uso Básico

```python
from suspicious_pattern_detector import SuspiciousPatternDetector

# Inicializar detector
detector = SuspiciousPatternDetector()

# Analisar logs
with open('logs.txt', 'r') as f:
    log_data = f.read()

results = detector.analyze_logs(log_data)

# Exibir resultados
print(f"Eventos suspeitos encontrados: {len(results['suspicious_events'])}")
```

### Uso com Configuração Personalizada

```python
detector = SuspiciousPatternDetector('config.json')
results = detector.analyze_logs(log_data)
detector.export_results('relatorio_seguranca.json')
```

### Execução via Linha de Comando

```bash
python suspicious_pattern_detector.py
```

## 🕵️ Detecções Implementadas

### 1. Tentativas de Login Múltiplas
- **Descrição**: Detecta múltiplas tentativas de login falhadas do mesmo usuário/IP
- **Event ID**: 4625 (Windows)
- **Severidade**: Medium
- **Threshold**: 5 tentativas em 10 minutos (configurável)

### 2. Ataques de Força Bruta
- **Descrição**: Identifica tentativas contra múltiplos usuários do mesmo IP
- **Event ID**: 4625 (Windows)
- **Severidade**: High
- **Critério**: 10+ tentativas contra 3+ usuários em 30 minutos

### 3. Atividade Fora do Horário
- **Descrição**: Monitora logins em horários não comerciais
- **Event ID**: 4624 (Windows)
- **Severidade**: Low
- **Horário**: 22:00 às 06:00 (configurável)

### 4. Atividade de Contas Admin
- **Descrição**: Monitora uso de contas administrativas
- **Event IDs**: 4624, 4625 (Windows)
- **Severidade**: High (falha), Medium (sucesso)

### 5. Processos Suspeitos
- **Descrição**: Detecta execução de comandos/ferramentas suspeitas
- **Event ID**: 4688 (Windows)
- **Severidade**: High
- **Exemplos**: PowerShell encoded, certutil, regsvr32

### 6. Anomalias Geográficas
- **Descrição**: Logins de múltiplos IPs em curto período
- **Event ID**: 4624 (Windows)
- **Severidade**: Medium
- **Critério**: 3+ IPs diferentes em menos de 1 hora

## 📄 Formato dos Logs

### Formato Esperado (CSV)

```
timestamp,event_id,username,source_ip,computer,description
2024-06-25 14:30:15,4625,jsilva,192.168.1.100,WORKSTATION01,Login failed for user jsilva
2024-06-25 14:31:30,4624,admin,10.0.0.50,SERVER01,Successful login for admin
```

### Campos Obrigatórios

- **timestamp**: Data/hora do evento (formato ISO ou compatível)
- **event_id**: ID do evento Windows (4624, 4625, 4688, etc.)
- **username**: Nome do usuário
- **source_ip**: IP de origem
- **computer**: Nome do computador
- **description**: Descrição detalhada do evento

## 💡 Exemplos

### Exemplo de Saída

```json
{
  "suspicious_events": [
    {
      "type": "Multiple Failed Logins",
      "severity": "Medium",
      "username": "jsilva",
      "source_ip": "192.168.1.100",
      "count": 6,
      "time_window": "2024-06-25 14:30:15 - 2024-06-25 14:40:15"
    }
  ],
  "summary": {
    "total_suspicious_events": 1,
    "severity_breakdown": {"Medium": 1},
    "type_breakdown": {"Multiple Failed Logins": 1}
  }
}
```

### Integração com SIEM

```python
# Exemplo de integração com Splunk/ELK
def send_to_siem(results):
    for event in results['suspicious_events']:
        siem_client.send_alert({
            'alert_type': event['type'],
            'severity': event['severity'],
            'details': event,
            'timestamp': datetime.now()
        })
```

## 🔧 Personalização

### Adicionando Nova Detecção

```python
def detect_custom_pattern(self, df: pd.DataFrame) -> List[Dict]:
    suspicious = []
    # Sua lógica de detecção aqui
    return suspicious

# Adicionar na função analyze_logs
detections.append(('Custom Pattern', self.detect_custom_pattern))
```

### Modificando Parser de Logs

```python
def parse_custom_log_format(self, log_data: str) -> pd.DataFrame:
    # Adapte para seu formato específico
    # Syslog, JSON, XML, etc.
    pass
```

## 📊 Monitoramento e Alertas

### Integração com Alertas

```python
# Configurar alertas por severidade
HIGH_SEVERITY_WEBHOOK = "https://hooks.slack.com/..."

def send_alert(event):
    if event['severity'] == 'High':
        requests.post(HIGH_SEVERITY_WEBHOOK, json={
            'text': f"🚨 ALERTA CRÍTICO: {event['type']}"
        })
```

### Métricas Recomendadas

- Taxa de eventos suspeitos por hora
- Top 10 IPs com mais atividade suspeita
- Usuários mais visados em ataques
- Horários de maior atividade maliciosa

## 🔄 Automação

### Execução Agendada (Cron)

```bash
# Executar a cada 15 minutos
*/15 * * * * /usr/bin/python3 /path/to/suspicious_pattern_detector.py
```

### Script de Monitoramento Contínuo

```python
import time
import os

def monitor_logs():
    detector = SuspiciousPatternDetector()
    
    while True:
        # Ler novos logs
        new_logs = fetch_latest_logs()
        
        if new_logs:
            results = detector.analyze_logs(new_logs)
            
            # Processar alertas críticos
            for event in results['suspicious_events']:
                if event['severity'] == 'High':
                    send_immediate_alert(event)
        
        time.sleep(300)  # 5 minutos
```

## 🐛 Troubleshooting

### Problemas Comuns

**Erro de parsing de data:**
```python
# Ajustar formato de data no parser
'timestamp': pd.to_datetime(parts[0], format='%Y-%m-%d %H:%M:%S')
```

**Logs vazios:**
```python
# Verificar formato dos logs
print(log_data[:200])  # Primeiros 200 caracteres
```

**Performance com logs grandes:**
```python
# Processar em chunks
chunk_size = 10000
for chunk in pd.read_csv('logs.csv', chunksize=chunk_size):
    results = detector.analyze_chunk(chunk)
```

## 📈 Performance

### Benchmarks

- **10.000 eventos**: ~2 segundos
- **100.000 eventos**: ~15 segundos
- **1.000.000 eventos**: ~2 minutos

### Otimizações

- Use `pd.read_csv()` para arquivos grandes
- Implemente processamento em chunks para datasets massivos
- Configure índices adequados para consultas frequentes

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/NovaDeteccao`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova detecção'`)
4. Push para a branch (`git push origin feature/NovaDeteccao`)
5. Abra um Pull Request


## 📋 TO-DO

- [ ] Suporte para logs Syslog
- [ ] Interface web para visualização
- [ ] Integração com APIs de Threat Intelligence
- [ ] Machine Learning para detecção de anomalias
- [ ] Suporte para múltiplos formatos de log
- [ ] Dashboard em tempo real


## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🙋‍♂️ Autores

- **GoetiaDEv** - *Desenvolvimento Inicial* - [GoetiaDEv](https://github.com/goetiaDEv)

## 🙏 Agradecimentos

- Comunidade de Cybersecurity
- Equipes de SOC que inspiraram este projeto
- Contribuidores open source

---

**⚠️ Aviso Legal**: Esta ferramenta é destinada apenas para uso legítimo em ambientes autorizados. O uso indevido é de responsabilidade do usuário.
