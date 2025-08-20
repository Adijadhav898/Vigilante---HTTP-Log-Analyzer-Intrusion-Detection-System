#!/usr/bin/env python3
"""
Vigilante - A custom HTTP log analyzer and basic intrusion detection system.
Monitors Apache/NGINX access logs in real-time and alerts on suspicious activity.
"""

import re
import time
import argparse
import sys
from collections import defaultdict
from datetime import datetime

class Vigilante:
    def __init__(self):
        self.request_log = defaultdict(list)
        self.alert_count = 0
        
    def parse_apache_log(self, line):
        """
        Parses a single line from an Apache Common Log Format.
        Example Line: 127.0.0.1 - - [01/Jan/2023:12:00:00 +0000] "GET /admin HTTP/1.1" 403 1234
        """
        # More robust pattern that handles different log formats
        log_pattern = r'(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\S+) (\S+)(?:"([^"]*)")?(?:"([^"]*)")?'
        match = re.match(log_pattern, line)
        if match:
            return {
                'ip': match.group(1),
                'time': match.group(4),
                'method': match.group(5),
                'url': match.group(6),
                'protocol': match.group(7),
                'status': match.group(8),
                'size': match.group(9),
                'raw_line': line.strip()
            }
        return None

    def detect_web_attack(self, parsed_log):
        """Detect common web attack patterns in the URL"""
        suspicious_patterns = [
            r'\/\.env',              # Laravel .env file exposure
            r'\/wp-admin',           # WordPress admin access
            r'\/admin',              # General admin access
            r'union.*select',        # SQL Injection attempt
            r'exec\(',               # Command Injection attempt
            r'\.\./',                # Path Traversal attack
            r'\/etc\/passwd',        # LFI attempt
            r'\/bin\/bash',          # Shell access attempt
            r'<script>',             # XSS attempt
            r'\.php\.',              # PHP filter attack
            r'\/\.git',              # Git directory exposure
            r'\/\.htaccess',         # htaccess access
            r'\/\.ssh',              # SSH directory access
            r'\/backup',             # Backup file access
            r'\/config',             # Configuration file access
            r'\/phpmyadmin',         # phpMyAdmin access
            r'\/mysql',              # MySQL admin
            r'\/shell',              # Shell access
            r'\/cmd',                # Command execution
            r'\/console',            # Console access
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, parsed_log['url'], re.IGNORECASE):
                return f"Web attack pattern detected: {pattern}"
        return None

    def detect_brute_force(self, parsed_log, time_window=10, max_requests=15):
        """Detect rapid-fire requests from a single IP"""
        current_time = time.time()
        ip = parsed_log['ip']
        
        # Add current request to the log
        self.request_log[ip].append(current_time)
        
        # Remove requests older than the time window
        self.request_log[ip] = [t for t in self.request_log[ip] if current_time - t < time_window]
        
        # Check if the number of requests exceeds the threshold
        if len(self.request_log[ip]) > max_requests:
            return f"Brute force/DoS detected from IP: {ip} ({len(self.request_log[ip])} requests in {time_window}s)"
        return None

    def detect_suspicious_user_agent(self, parsed_log):
        """Detect suspicious or missing user agents"""
        # Check for common malicious user agents
        malicious_agents = [
            'nikto', 'sqlmap', 'wget', 'curl', 'nmap', 'nessus',
            'acunetix', 'burpsuite', 'metasploit', 'hydra', 'john',
            'dirbuster', 'gobuster', 'wfuzz', 'sqlsus', 'havij',
            'sqlninja', 'arachni', 'skipfish', 'w3af', 'zap'
        ]
        
        raw_line_lower = parsed_log['raw_line'].lower()
        for agent in malicious_agents:
            if agent in raw_line_lower:
                return f"Suspicious user agent detected: {agent}"
        return None

    def detect_http_errors(self, parsed_log):
        """Detect patterns of HTTP errors that might indicate scanning"""
        error_codes = ['404', '403', '500', '401']
        if parsed_log['status'] in error_codes:
            return f"HTTP Error {parsed_log['status']} detected for {parsed_log['url']}"
        return None

    def detect_sensitive_files(self, parsed_log):
        """Detect access to sensitive files"""
        sensitive_files = [
            r'\.sql$', r'\.env$', r'\.bak$', r'\.old$', r'\.tar$', 
            r'\.gz$', r'\.zip$', r'\.rar$', r'\.log$', r'\.cfg$',
            r'\.conf$', r'\.ini$', r'\.key$', r'\.pem$', r'\.crt$'
        ]
        
        for pattern in sensitive_files:
            if re.search(pattern, parsed_log['url'], re.IGNORECASE):
                return f"Sensitive file access detected: {pattern}"
        return None

    def print_alert(self, alert_type, parsed_log, message):
        """Print a formatted alert message"""
        self.alert_count += 1
        print(f"\n\033[91m[!] ALERT #{self.alert_count}: {alert_type}\033[0m")
        print(f"\033[93m    Time: {parsed_log['time']}\033[0m")
        print(f"\033[93m    Source IP: {parsed_log['ip']}\033[0m")
        print(f"\033[93m    Request: {parsed_log['method']} {parsed_log['url']}\033[0m")
        print(f"\033[93m    Status: {parsed_log['status']}\033[0m")
        print(f"\033[93m    Details: {message}\033[0m")
        print(f"\033[90m    Raw: {parsed_log['raw_line']}\033[0m")
        print("-" * 80)

    def print_stats(self, total_lines, start_time):
        """Print monitoring statistics"""
        duration = time.time() - start_time
        print(f"\n\033[92m[+] Monitoring Statistics:\033[0m")
        print(f"    Duration: {duration:.2f} seconds")
        print(f"    Lines processed: {total_lines}")
        print(f"    Alerts triggered: {self.alert_count}")
        print(f"    Requests/sec: {total_lines/duration:.2f}" if duration > 0 else "")

    def monitor_log(self, file_path, follow=True):
        """Main monitoring function"""
        print(f"\033[94m[+] Starting Vigilante monitor on {file_path}...\033[0m")
        print(f"\033[94m[+] Press Ctrl+C to stop.\033[0m")
        print(f"\033[94m[+] Monitoring started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
        print("-" * 80)
        
        total_lines = 0
        start_time = time.time()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                # Go to the end of the file if following
                if follow:
                    file.seek(0, 2)
                
                while True:
                    line = file.readline()
                    if not line:
                        if not follow:
                            break  # Exit if not following and reached end
                        time.sleep(0.1)  # Sleep briefly if no new line
                        continue
                    
                    total_lines += 1
                    
                    # Parse the log line
                    parsed = self.parse_apache_log(line)
                    if not parsed:
                        continue  # Skip unparseable lines
                    
                    # Apply all security rules
                    alerts = []
                    
                    if alert := self.detect_web_attack(parsed):
                        alerts.append(('WEB_ATTACK', alert))
                    
                    if alert := self.detect_brute_force(parsed):
                        alerts.append(('BRUTE_FORCE', alert))
                    
                    if alert := self.detect_http_errors(parsed):
                        alerts.append(('HTTP_ERROR', alert))
                    
                    if alert := self.detect_suspicious_user_agent(parsed):
                        alerts.append(('SUSPICIOUS_UA', alert))
                    
                    if alert := self.detect_sensitive_files(parsed):
                        alerts.append(('SENSITIVE_FILE', alert))
                    
                    # Print all alerts for this request
                    for alert_type, message in alerts:
                        self.print_alert(alert_type, parsed, message)
                        
                    # Print progress every 100 lines
                    if total_lines % 100 == 0:
                        print(f"\033[90m[+] Processed {total_lines} lines...\033[0m")
                        
        except KeyboardInterrupt:
            print(f"\n\033[94m[+] Monitoring interrupted by user.\033[0m")
        except FileNotFoundError:
            print(f"\033[91m[!] Error: File '{file_path}' not found.\033[0m")
            return
        except Exception as e:
            print(f"\033[91m[!] Error reading file: {e}\033[0m")
            return
        
        self.print_stats(total_lines, start_time)

    def analyze_existing_log(self, file_path):
        """Analyze an existing log file (not real-time)"""
        print(f"\033[94m[+] Analyzing existing log file: {file_path}\033[0m")
        self.monitor_log(file_path, follow=False)

def main():
    parser = argparse.ArgumentParser(
        description="Vigilante - Custom HTTP Log Analyzer & Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s access.log              # Monitor live log file
  %(prog)s --analyze access.log    # Analyze existing log file
  %(prog)s --no-color access.log   # Disable colored output
        """
    )
    
    parser.add_argument("logfile", nargs="?", help="Path to the log file to monitor")
    parser.add_argument("--analyze", action="store_true", help="Analyze existing log file (not real-time)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        # Override print functions to remove colors
        import builtins
        original_print = builtins.print
        
        def no_color_print(*args, **kwargs):
            # Remove ANSI color codes
            args = [re.sub(r'\033\[[0-9;]*m', '', str(arg)) for arg in args]
            original_print(*args, **kwargs)
        
        builtins.print = no_color_print
    
    vigilante = Vigilante()
    
    if args.logfile:
        if args.analyze:
            vigilante.analyze_existing_log(args.logfile)
        else:
            vigilante.monitor_log(args.logfile)
    else:
        parser.print_help()
        print("\n[!] Error: Please specify a log file")
        sys.exit(1)

if __name__ == "__main__":
    main()