#!/usr/bin/env python3


import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import re
import json
from collections import defaultdict, Counter
import logging
from typing import Dict, List, Tuple, Any

class SuspiciousPatternDetector:
    def __init__(self, config_file=None):
        
        self.setup_logging()
        self.suspicious_events = []
        
        self.config = {
            'failed_login_threshold': 5,
            'failed_login_window_minutes': 10,
            'brute_force_threshold': 10,
            'brute_force_window_minutes': 30,
            'off_hours_start': 22,
            'off_hours_end': 6,
            'suspicious_processes': [
                'powershell.exe -enc', 'cmd.exe /c', 'wscript.exe', 'cscript.exe',
                'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe'
            ],
            'suspicious_file_extensions': ['.bat', '.ps1', '.vbs', '.js', '.jar', '.scr'],
            'admin_accounts': ['administrator', 'admin', 'root'],
            'critical_systems': ['dc01', 'exchange01', 'fileserver01']
        }
        
        if config_file:
            self.load_config(config_file)
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('suspicious_patterns.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_config(self, config_file: str):
        try:
            with open(config_file, 'r') as f:
                custom_config = json.load(f)
                self.config.update(custom_config)
        except Exception as e:
            self.logger.error(f"Erro ao carregar configuração: {e}")
    
    def parse_windows_event_log(self, log_data: str) -> pd.DataFrame:
        events = []
        lines = log_data.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            try:
                parts = line.split(',')
                if len(parts) >= 6:
                    event = {
                        'timestamp': pd.to_datetime(parts[0]),
                        'event_id': int(parts[1]),
                        'username': parts[2].strip(),
                        'source_ip': parts[3].strip(),
                        'computer': parts[4].strip(),
                        'description': parts[5].strip()
                    }
                    events.append(event)
            except Exception as e:
                self.logger.warning(f"Erro ao processar linha: {line[:50]}... - {e}")
                continue
        
        return pd.DataFrame(events)
    
    def detect_failed_login_patterns(self, df: pd.DataFrame) -> List[Dict]:
        """Detecta padrões de tentativas de login falhadas"""
        suspicious = []
       
        failed_logins = df[df['event_id'] == 4625].copy()
        
        if failed_logins.empty:
            return suspicious
        
        for (username, source_ip), group in failed_logins.groupby(['username', 'source_ip']):
            group = group.sort_values('timestamp')
            
            time_window = timedelta(minutes=self.config['failed_login_window_minutes'])
            
            for i, row in group.iterrows():
                window_start = row['timestamp']
                window_end = window_start + time_window
                
                window_events = group[
                    (group['timestamp'] >= window_start) & 
                    (group['timestamp'] <= window_end)
                ]
                
                if len(window_events) >= self.config['failed_login_threshold']:
                    suspicious.append({
                        'type': 'Multiple Failed Logins',
                        'severity': 'Medium',
                        'username': username,
                        'source_ip': source_ip,
                        'count': len(window_events),
                        'time_window': f"{window_start} - {window_end}",
                        'computers': list(window_events['computer'].unique())
                    })
                    break
        
        return suspicious
    
    def detect_brute_force_attacks(self, df: pd.DataFrame) -> List[Dict]:
        """Detecta ataques de força bruta"""
        suspicious = []
        
        failed_logins = df[df['event_id'] == 4625].copy()
        
        if failed_logins.empty:
            return suspicious
        
        for source_ip, group in failed_logins.groupby('source_ip'):
            group = group.sort_values('timestamp')
            unique_users = group['username'].nunique()
            
            if unique_users >= 3:
                time_window = timedelta(minutes=self.config['brute_force_window_minutes'])
                
                for i, row in group.iterrows():
                    window_start = row['timestamp']
                    window_end = window_start + time_window
                    
                    window_events = group[
                        (group['timestamp'] >= window_start) & 
                        (group['timestamp'] <= window_end)
                    ]
                    
                    if len(window_events) >= self.config['brute_force_threshold']:
                        suspicious.append({
                            'type': 'Brute Force Attack',
                            'severity': 'High',
                            'source_ip': source_ip,
                            'total_attempts': len(window_events),
                            'unique_users': window_events['username'].nunique(),
                            'time_window': f"{window_start} - {window_end}",
                            'targeted_users': list(window_events['username'].unique())
                        })
                        break
        
        return suspicious
    
    def detect_off_hours_activity(self, df: pd.DataFrame) -> List[Dict]:
        """Detecta atividade em horários não comerciais"""
        suspicious = []
        
        successful_logins = df[df['event_id'] == 4624].copy()
        
        if successful_logins.empty:
            return suspicious
        
        for _, row in successful_logins.iterrows():
            hour = row['timestamp'].hour
            
            if hour >= self.config['off_hours_start'] or hour <= self.config['off_hours_end']:

                if not any(svc in row['username'].lower() for svc in ['service', 'system', '$']):
                    suspicious.append({
                        'type': 'Off-Hours Login',
                        'severity': 'Low',
                        'username': row['username'],
                        'source_ip': row['source_ip'],
                        'computer': row['computer'],
                        'timestamp': row['timestamp'],
                        'hour': hour
                    })
        
        return suspicious
    
    def detect_admin_account_activity(self, df: pd.DataFrame) -> List[Dict]:
        suspicious = []
        
        admin_events = df[df['username'].str.lower().isin(self.config['admin_accounts'])].copy()
        
        for _, row in admin_events.iterrows():
            if row['event_id'] == 4625:  # Login falhado
                suspicious.append({
                    'type': 'Admin Account Failed Login',
                    'severity': 'High',
                    'username': row['username'],
                    'source_ip': row['source_ip'],
                    'computer': row['computer'],
                    'timestamp': row['timestamp']
                })
            elif row['event_id'] == 4624:  # Login bem-sucedido
                suspicious.append({
                    'type': 'Admin Account Login',
                    'severity': 'Medium',
                    'username': row['username'],
                    'source_ip': row['source_ip'],
                    'computer': row['computer'],
                    'timestamp': row['timestamp']
                })
        
        return suspicious
    
    def detect_suspicious_processes(self, df: pd.DataFrame) -> List[Dict]:
        """Detecta execução de processos suspeitos"""
        suspicious = []
        
        process_events = df[df['event_id'] == 4688].copy()
        
        for _, row in process_events.iterrows():
            description = row['description'].lower()
            
            for suspicious_process in self.config['suspicious_processes']:
                if suspicious_process.lower() in description:
                    suspicious.append({
                        'type': 'Suspicious Process Execution',
                        'severity': 'High',
                        'computer': row['computer'],
                        'username': row['username'],
                        'process': suspicious_process,
                        'full_command': row['description'],
                        'timestamp': row['timestamp']
                    })
                    break
        
        return suspicious
    
    def detect_geographic_anomalies(self, df: pd.DataFrame) -> List[Dict]:
        """Detecta logins de localizações geográficas anômalas (exemplo básico)"""
        suspicious = []
        
        successful_logins = df[df['event_id'] == 4624].copy()
        
        for username, group in successful_logins.groupby('username'):
            unique_ips = group['source_ip'].unique()
            
            if len(unique_ips) > 3:
                time_span = group['timestamp'].max() - group['timestamp'].min()
                
                if time_span.total_seconds() < 3600:  # Menos de 1 hora
                    suspicious.append({
                        'type': 'Multiple Geographic Locations',
                        'severity': 'Medium',
                        'username': username,
                        'ip_addresses': list(unique_ips),
                        'time_span_minutes': int(time_span.total_seconds() / 60),
                        'first_login': group['timestamp'].min(),
                        'last_login': group['timestamp'].max()
                    })
        
        return suspicious
    
    def analyze_logs(self, log_data: str) -> Dict[str, Any]:
        """Função principal para análise de logs"""
        self.logger.info("Iniciando análise de padrões suspeitos...")
        
        df = self.parse_windows_event_log(log_data)
        
        if df.empty:
            self.logger.warning("Nenhum evento válido encontrado nos logs")
            return {'suspicious_events': [], 'summary': {}}
        
        self.logger.info(f"Analisando {len(df)} eventos...")
        
        all_suspicious = []
        
        detections = [
            ('Failed Login Patterns', self.detect_failed_login_patterns),
            ('Brute Force Attacks', self.detect_brute_force_attacks),
            ('Off-Hours Activity', self.detect_off_hours_activity),
            ('Admin Account Activity', self.detect_admin_account_activity),
            ('Suspicious Processes', self.detect_suspicious_processes),
            ('Geographic Anomalies', self.detect_geographic_anomalies)
        ]
        
        for detection_name, detection_func in detections:
            try:
                results = detection_func(df)
                all_suspicious.extend(results)
                self.logger.info(f"{detection_name}: {len(results)} eventos suspeitos encontrados")
            except Exception as e:
                self.logger.error(f"Erro em {detection_name}: {e}")
        
        summary = self.generate_summary(all_suspicious, df)
        
        self.suspicious_events = all_suspicious
        
        return {
            'suspicious_events': all_suspicious,
            'summary': summary,
            'total_events_analyzed': len(df)
        }
    
    def generate_summary(self, suspicious_events: List[Dict], df: pd.DataFrame) -> Dict:
        """Gera sumário da análise"""
        severity_count = Counter([event['severity'] for event in suspicious_events])
        type_count = Counter([event['type'] for event in suspicious_events])
        
        return {
            'total_suspicious_events': len(suspicious_events),
            'severity_breakdown': dict(severity_count),
            'type_breakdown': dict(type_count),
            'analysis_period': {
                'start': df['timestamp'].min().isoformat() if not df.empty else None,
                'end': df['timestamp'].max().isoformat() if not df.empty else None
            }
        }
    
    def export_results(self, filename: str = None):
        """Exporta resultados para arquivo JSON"""
        if not filename:
            filename = f"suspicious_patterns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.suspicious_events, f, indent=2, default=str)
        
        self.logger.info(f"Resultados exportados para {filename}")

if __name__ == "__main__":
    sample_log_data = """
2024-06-25 14:30:15,4625,jsilva,192.168.1.100,WORKSTATION01,Login failed for user jsilva
2024-06-25 14:30:30,4625,jsilva,192.168.1.100,WORKSTATION01,Login failed for user jsilva
2024-06-25 14:30:45,4625,jsilva,192.168.1.100,WORKSTATION01,Login failed for user jsilva
2024-06-25 14:31:00,4625,jsilva,192.168.1.100,WORKSTATION01,Login failed for user jsilva
2024-06-25 14:31:15,4625,jsilva,192.168.1.100,WORKSTATION01,Login failed for user jsilva
2024-06-25 14:31:30,4625,jsilva,192.168.1.100,WORKSTATION01,Login failed for user jsilva
2024-06-25 02:15:22,4624,admin,10.0.0.50,SERVER01,Successful login for admin
2024-06-25 14:45:10,4688,mpereira,192.168.1.50,WORKSTATION02,Process created: powershell.exe -enc base64command
2024-06-25 15:00:00,4625,administrator,192.168.1.200,WORKSTATION03,Login failed for administrator
"""
    
    detector = SuspiciousPatternDetector()
    
    results = detector.analyze_logs(sample_log_data)

    print("\n=== SUMÁRIO DA ANÁLISE ===")
    print(json.dumps(results['summary'], indent=2))
    
    print(f"\n=== EVENTOS SUSPEITOS ({len(results['suspicious_events'])}) ===")
    for event in results['suspicious_events']:
        print(f"\n[{event['severity']}] {event['type']}")
        for key, value in event.items():
            if key not in ['type', 'severity']:
                print(f"  {key}: {value}")
    
    detector.export_results()
