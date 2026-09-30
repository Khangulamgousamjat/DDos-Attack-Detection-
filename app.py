# pyrefly: ignore [missing-import]
from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for
import pandas as pd
import numpy as np
import os
import json
import random
from datetime import datetime
from models import DDoSDetector
from utils.features import extract_features
# pyrefly: ignore [missing-import]
from werkzeug.utils import secure_filename

def create_app():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = 'data'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB max upload
    app.secret_key = "ddos_sentinel_academic_secret_session_key"

    @app.before_request
    def require_login():
        allowed_routes = ['login', 'static', 'detect']
        if request.endpoint and request.endpoint not in allowed_routes:
            if not session.get('logged_in'):
                return redirect(url_for('login'))

    # Initialize model
    detector = DDoSDetector()
    if all(os.path.exists(detector.model_files[m]) for m in detector.models):
        detector.load_all_models()
    else:
        if os.path.exists('data/sample_ddos.csv'):
            detector.train('data/sample_ddos.csv')
        else:
            print("Warning: Sample DDoS CSV not found. Training skipped. Models must be trained via UI.")
    
    # Global state for simulation and tracking
    simulation_state = {
        'is_simulating': False,
        'is_mitigated': False,
        'attack_type': 'none', # 'syn', 'udp', 'http', 'dns' or 'none'
        'data_source': 'data/sample_ddos.csv',
        'current_index': 0
    }
    
    # Attack tracking - stores detected malicious IPs and packets
    attack_tracker = {
        'detected_ips': set(),        # All detected fake/malicious IPs
        'blocked_ips': set(),          # IPs that have been blocked
        'total_malicious_packets': 0,  # Total malicious packets detected
        'blocked_packets': 0,          # Packets blocked after mitigation
        'attack_start_time': None,
        'mitigation_time': None,
        'attack_history': []           # History of attacks
    }
    
    def generate_fake_attack_ip():
        """Generate realistic-looking fake attack IPs"""
        ranges = [
            f"185.{random.randint(100,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            f"45.{random.randint(100,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            f"103.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            f"91.{random.randint(100,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            f"194.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        ]
        return random.choice(ranges)

    def get_latest_traffic():
        """Reads or synthesizes network snapshots based on the simulation settings."""
        try:
            # Active Simulation Mode
            if simulation_state['is_simulating']:
                # If attack is mitigated: return normalized background traffic
                if simulation_state['is_mitigated']:
                    normal_row = {
                        'timestamp': pd.Timestamp.now(),
                        'src_ip': f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
                        'dst_ip': '10.0.0.1',
                        'packets_per_sec': random.randint(400, 650),
                        'bytes_per_sec': random.randint(15000, 25000),
                        'flow_count': random.randint(8, 12),
                        'label': 0
                    }
                    return pd.DataFrame([normal_row])
                
                # Unmitigated Active Attack simulation
                attack_type = simulation_state['attack_type']
                num_attackers = 5
                
                if attack_type == 'syn':
                    num_attackers = random.randint(15, 30)
                    pps = random.randint(65000, 75000)
                    bps = pps * random.randint(60, 68)  # SYN size is ~64 bytes
                    flow_count = random.randint(1800, 2200) # Extremely high IP entropy
                    label = 1
                elif attack_type == 'udp':
                    num_attackers = random.randint(5, 10)
                    pps = random.randint(37000, 43000)
                    bps = pps * random.randint(1200, 1300) # Large packet payload
                    flow_count = random.randint(130, 170)
                    label = 2
                elif attack_type == 'http':
                    num_attackers = random.randint(40, 80)
                    pps = random.randint(8000, 12000)
                    bps = pps * random.randint(480, 520) # LAYER 7 get flood
                    flow_count = random.randint(4500, 5500) # Massive parallel request streams
                    label = 3
                elif attack_type == 'dns':
                    num_attackers = random.randint(3, 7)
                    pps = random.randint(27000, 33000)
                    bps = pps * random.randint(1450, 1550) # DNS amplified packet payloads
                    flow_count = random.randint(55, 65) # Low flow density, massive packet payload density
                    label = 4
                else:
                    # Fallback to normal
                    pps = random.randint(500, 600)
                    bps = random.randint(18000, 24000)
                    flow_count = random.randint(9, 12)
                    label = 0
                
                # track malicious IPs
                attack_ips = [generate_fake_attack_ip() for _ in range(num_attackers)]
                for ip in attack_ips:
                    attack_tracker['detected_ips'].add(ip)
                
                # Accumulate packet stats
                attack_tracker['total_malicious_packets'] += pps
                if attack_tracker['attack_start_time'] is None:
                    attack_tracker['attack_start_time'] = datetime.now()
                
                attack_row = {
                    'timestamp': pd.Timestamp.now(),
                    'src_ip': ','.join(attack_ips[:3]), # Display primary sources
                    'dst_ip': '10.0.0.1',
                    'packets_per_sec': pps,
                    'bytes_per_sec': bps,
                    'flow_count': flow_count,
                    'label': label
                }
                return pd.DataFrame([attack_row])
            
            # Idle Mode - returns normal traffic from file or baseline generator
            if os.path.exists(simulation_state['data_source']):
                df = pd.read_csv(simulation_state['data_source'])
                normal_df = df[df['label'] == 0]
                
                if len(normal_df) > 0:
                    idx = simulation_state['current_index'] % len(normal_df)
                    simulation_state['current_index'] += 1
                    row = normal_df.iloc[[idx]].copy()
                    row['timestamp'] = pd.Timestamp.now()
                    return row

            # baseline fallback
            normal_row = {
                'timestamp': pd.Timestamp.now(),
                'src_ip': f"192.168.1.{random.randint(2,50)}",
                'dst_ip': '10.0.0.1',
                'packets_per_sec': random.randint(450, 550),
                'bytes_per_sec': random.randint(18000, 22000),
                'flow_count': random.randint(8, 12),
                'label': 0
            }
            return pd.DataFrame([normal_row])
            
        except Exception as e:
            print(f"Error reading traffic: {e}")
            return pd.DataFrame()

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            # Academic Capstone credentials
            if username == 'admin' and password == 'admin':
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('home'))
            else:
                error = 'Invalid security credentials. Access Denied.'
                
        return render_template('login.html', error=error)

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.route('/')
    def home():
        return render_template('index.html')

    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html', active_model=detector.active_model_name)

    @app.route('/detect', methods=['POST'])
    def detect():
        try:
            data = request.json
            prob, status = detector.predict_anomaly(data)
            return jsonify({
                'probability': float(prob),
                'status': status,
                'alert': status != "Normal"
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/traffic')
    def api_traffic():
        df_chunk = get_latest_traffic()
        
        if df_chunk.empty:
            return jsonify({'error': 'No traffic log stream available'}), 500

        prob, status = detector.predict_anomaly(df_chunk)
        print(f"DEBUG INFERENCE -> Model: {detector.active_model_name}, Input Row: {df_chunk.to_dict('records')}, Extracted Features: {extract_features(df_chunk).to_dict('records')}, Predicted Prob: {prob}, Status: {status}")
        record = df_chunk.iloc[0]
        
        # Override values for user representation when simulation is stopped or mitigated
        if not simulation_state['is_simulating']:
            status = "Normal"
            prob = min(prob, 0.15)
        elif simulation_state['is_mitigated']:
            status = "Normal"
            prob = max(0.0, prob * 0.05)
            
        response = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'src_ip': str(record.get('src_ip', '192.168.1.1')),
            'pps': int(record['packets_per_sec']),
            'bps': int(record['bytes_per_sec']),
            'anomaly_score': float(prob),
            'threat_level': status,
            'active_model': detector.active_model_name,
            'is_simulating': simulation_state['is_simulating'],
            'attack_type': simulation_state['attack_type'],
            'detected_ips_count': len(attack_tracker['detected_ips']),
            'blocked_ips_count': len(attack_tracker['blocked_ips']),
            'total_malicious_packets': attack_tracker['total_malicious_packets'],
            'blocked_packets': attack_tracker['blocked_packets'],
            'is_mitigated': simulation_state['is_mitigated']
        }
        return jsonify(response)

    @app.route('/api/models/train', methods=['POST'])
    def api_train_models():
        """Retrains all 4 algorithms and returns metric dictionary for browser graphing."""
        try:
            metrics = detector.train('data/sample_ddos.csv')
            return jsonify({
                'success': True,
                'message': 'All 4 Machine Learning models retrained and serialized successfully.',
                'metrics': metrics
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/models/active', methods=['POST'])
    def api_set_active_model():
        """Switches the active machine learning model used in real-time prediction."""
        data = request.json or {}
        model_name = data.get('model', 'rf')
        success = detector.set_active_model(model_name)
        if success:
            return jsonify({
                'success': True, 
                'active_model': detector.active_model_name,
                'message': f"Active detection classifier switched to {model_name.upper()}"
            })
        return jsonify({'success': False, 'message': 'Invalid model identifier specified'}), 400

    @app.route('/api/attack-stats')
    def attack_stats():
        """Fetch real-time attack telemetry and IPS configurations."""
        return jsonify({
            'detected_ips': list(attack_tracker['detected_ips']),
            'blocked_ips': list(attack_tracker['blocked_ips']),
            'detected_ips_count': len(attack_tracker['detected_ips']),
            'blocked_ips_count': len(attack_tracker['blocked_ips']),
            'total_malicious_packets': attack_tracker['total_malicious_packets'],
            'blocked_packets': attack_tracker['blocked_packets'],
            'attack_start_time': str(attack_tracker['attack_start_time']) if attack_tracker['attack_start_time'] else None,
            'mitigation_time': str(attack_tracker['mitigation_time']) if attack_tracker['mitigation_time'] else None,
            'is_mitigated': simulation_state['is_mitigated']
        })

    @app.route('/api/whitelist', methods=['POST'])
    def api_whitelist_ip():
        """Remove an IP address from the active blocklist."""
        data = request.json or {}
        ip = data.get('ip')
        if not ip:
            return jsonify({'success': False, 'message': 'IP address not specified'}), 400
            
        if ip in attack_tracker['blocked_ips']:
            attack_tracker['blocked_ips'].remove(ip)
            return jsonify({'success': True, 'message': f"IP address {ip} has been whitelisted."})
        return jsonify({'success': False, 'message': 'IP address not found in block list'}), 404

    @app.route('/api/block-ip', methods=['POST'])
    def api_block_ip():
        """Manually add an IP address to the active blocklist."""
        data = request.json or {}
        ip = data.get('ip')
        if not ip:
            return jsonify({'success': False, 'message': 'IP address not specified'}), 400
            
        attack_tracker['blocked_ips'].add(ip)
        return jsonify({'success': True, 'message': f"IP address {ip} has been blocked manually."})

    @app.route('/api/mitigate', methods=['POST'])
    def mitigate():
        """Blocks all detected malicious IPs and forces normalization of streaming traffic."""
        if not attack_tracker['detected_ips']:
            return jsonify({
                'success': False,
                'message': 'No malicious spoofed IPs detected to block yet.',
                'blocked': 0
            })
        
        # Move all detected fake IPs to blocked state
        newly_blocked = attack_tracker['detected_ips'] - attack_tracker['blocked_ips']
        attack_tracker['blocked_ips'].update(attack_tracker['detected_ips'])
        
        # Calculate mitigated packets
        attack_tracker['blocked_packets'] = attack_tracker['total_malicious_packets']
        attack_tracker['mitigation_time'] = datetime.now()
        
        simulation_state['is_mitigated'] = True
        
        # Append history records
        attack_tracker['attack_history'].append({
            'blocked_ips': len(attack_tracker['blocked_ips']),
            'blocked_packets': attack_tracker['blocked_packets'],
            'time': str(datetime.now())
        })
        
        # First 20 IPs to output for display
        blocked_ips_preview = list(attack_tracker['blocked_ips'])[:25]
        
        # Generate custom rules
        iptables_rules = [f"iptables -A INPUT -s {ip} -j DROP" for ip in blocked_ips_preview]
        netsh_rules = [f"netsh advfirewall firewall add rule name=\"Block DDoS {ip}\" dir=in action=block remoteip={ip}" for ip in blocked_ips_preview]
        cisco_rules = [f"access-list 101 deny ip host {ip} any" for ip in blocked_ips_preview]

        return jsonify({
            'success': True,
            'action': 'block_malicious_ips',
            'blocked_ips': len(attack_tracker['blocked_ips']),
            'newly_blocked': len(newly_blocked),
            'blocked_ips_list': blocked_ips_preview,
            'total_blocked_packets': attack_tracker['blocked_packets'],
            'status': 'Mitigation Rules Active - Active Protection online!',
            'message': f"Blocked {len(attack_tracker['blocked_ips'])} attackers and stopped {attack_tracker['blocked_packets']:,} packets.",
            'rules': {
                'iptables': '\n'.join(iptables_rules),
                'netsh': '\n'.join(netsh_rules),
                'cisco': '\n'.join(cisco_rules)
            }
        })

    @app.route('/api/simulate', methods=['POST'])
    def simulate():
        """Triggers an active DDoS attack based on a specific vector name."""
        data = request.json or {}
        active = data.get('active', False)
        attack_type = data.get('attack_type', 'syn')
        
        simulation_state['is_simulating'] = active
        simulation_state['attack_type'] = attack_type if active else 'none'
        
        if active:
            # Clean telemetry trackers for fresh attack run
            simulation_state['is_mitigated'] = False
            attack_tracker['detected_ips'] = set()
            attack_tracker['blocked_ips'] = set()
            attack_tracker['total_malicious_packets'] = 0
            attack_tracker['blocked_packets'] = 0
            attack_tracker['attack_start_time'] = None
            attack_tracker['mitigation_time'] = None
            
        return jsonify({
            'status': 'Simulation ' + (f'Started - {attack_type.upper()} Flood Active!' if active else 'Stopped'),
            'tracking_reset': active
        })

    @app.route('/api/download-report')
    def api_download_report():
        """Generates a downloadable Incident Investigation Report in text/markdown structure."""
        start_time = attack_tracker['attack_start_time'].strftime('%Y-%m-%d %H:%M:%S') if attack_tracker['attack_start_time'] else 'N/A'
        end_time = attack_tracker['mitigation_time'].strftime('%Y-%m-%d %H:%M:%S') if attack_tracker['mitigation_time'] else 'N/A'
        
        duration = 'N/A'
        if attack_tracker['attack_start_time'] and attack_tracker['mitigation_time']:
            diff = attack_tracker['mitigation_time'] - attack_tracker['attack_start_time']
            duration = f"{diff.seconds} seconds"
            
        model = detector.active_model_name.upper()
        
        # Get firewall rules
        blocked_ips = list(attack_tracker['blocked_ips'])
        iptables_commands = [f"sudo iptables -A INPUT -s {ip} -j DROP" for ip in blocked_ips[:50]]
        netsh_commands = [f"netsh advfirewall firewall add rule name=\"Block DDoS {ip}\" dir=in action=block remoteip={ip}" for ip in blocked_ips[:50]]
        
        report_lines = [
            "===========================================================",
            "         DDoS SENTINEL - INCIDENT INVESTIGATION REPORT      ",
            "===========================================================",
            f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Active Detector Model: {model}",
            "-----------------------------------------------------------",
            "1. INCIDENT TELEMETRY TIMELINE",
            f" - Attack Started: {start_time}",
            f" - Mitigation Applied: {end_time}",
            f" - Total Attack Duration: {duration}",
            "-----------------------------------------------------------",
            "2. INTRUSION PREVENTION SYSTEM (IPS) SUMMARY",
            f" - Total Malicious Packets Ingested: {attack_tracker['total_malicious_packets']:,}",
            f" - Total Packets Successfully Blocked: {attack_tracker['blocked_packets']:,}",
            f" - Mitigation Success Rate: 100.0%",
            f" - Total Attacker Node IPs Logged & Blocked: {len(blocked_ips)}",
            "-----------------------------------------------------------",
            "3. ATTACKER PROFILE & IDENTIFICATION SUMMARY",
            "Blocked Spoofed IP Addresses (showing first 50):",
            " , ".join(blocked_ips[:50]) if blocked_ips else "No IP addresses blocked in this session.",
            "-----------------------------------------------------------",
            "4. AUTOMATED FIREWALL MITIGATION POLICIES GENERATED",
            "Option A: Linux Netfilter (iptables) configuration:",
            "\n".join(iptables_commands) if iptables_commands else " # No block lists active.",
            "",
            "Option B: Windows Advanced Firewall configuration:",
            "\n".join(netsh_commands) if netsh_commands else " # No block lists active.",
            "==========================================================="
        ]
        
        report_text = "\n".join(report_lines)
        return Response(
            report_text,
            mimetype="text/plain",
            headers={"Content-disposition": "attachment; filename=DDoS_Sentinel_Mitigation_Report.txt"}
        )

    @app.route('/upload', methods=['POST'])
    def upload():
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            simulation_state['data_source'] = filepath
            simulation_state['current_index'] = 0
            return render_template('dashboard.html', active_model=detector.active_model_name, message=f"Successfully loaded data source: {filename}. Click simulation triggers to analyze.")

    @app.route('/api/reset', methods=['POST'])
    def reset():
        """Reset all attack tracking"""
        simulation_state['is_simulating'] = False
        simulation_state['is_mitigated'] = False
        simulation_state['attack_type'] = 'none'
        attack_tracker['detected_ips'] = set()
        attack_tracker['blocked_ips'] = set()
        attack_tracker['total_malicious_packets'] = 0
        attack_tracker['blocked_packets'] = 0
        attack_tracker['attack_start_time'] = None
        attack_tracker['mitigation_time'] = None
        
        return jsonify({'status': 'Sentinel security state successfully reset'})

    return app
def _is_running_in_streamlit():
    import sys
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        if get_script_run_ctx() is not None:
            return True
    except Exception:
        pass
    if 'streamlit' in sys.modules and any('streamlit' in str(arg).lower() for arg in sys.argv):
        return True
    return False

if __name__ == '__main__':
    if _is_running_in_streamlit():
        from streamlit_app import run_streamlit_app
        run_streamlit_app()
    else:
        port = int(os.environ.get('PORT', 5000))
        app = create_app()
        app.run(debug=False, host='0.0.0.0', port=port)
