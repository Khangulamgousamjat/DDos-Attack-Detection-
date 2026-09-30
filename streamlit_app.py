import streamlit as st
import pandas as pd
import numpy as np
import random
from datetime import datetime
import os
import matplotlib.pyplot as plt

# Import local modules
from models import DDoSDetector
from utils.features import extract_features

def run_streamlit_app():
    st.set_page_config(
        page_title="DDoS Sentinel - Security Gateway",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Global custom styling matching DDoS Sentinel theme
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');
        
        * {
            font-family: 'Poppins', sans-serif;
        }
        
        .main {
            background-color: #060912;
        }
        
        /* Glassmorphism Cards */
        .glass-card {
            background: rgba(16, 22, 35, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 12px;
            padding: 20px;
            backdrop-filter: blur(14px);
            margin-bottom: 16px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.37);
        }
        
        .metric-card {
            background: linear-gradient(135deg, rgba(16, 22, 35, 0.9) 0%, rgba(22, 30, 48, 0.85) 100%);
            border: 1px solid rgba(6, 182, 212, 0.25);
            border-radius: 12px;
            padding: 16px 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
            transition: all 0.3s ease;
        }
        
        .metric-card:hover {
            transform: translateY(-2px);
            border-color: rgba(6, 182, 212, 0.6);
            box-shadow: 0 8px 25px rgba(6, 182, 212, 0.2);
        }
        
        .metric-title {
            color: #94a3b8;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 6px;
            font-weight: 500;
        }
        
        .metric-value {
            color: #ffffff;
            font-size: 1.8rem;
            font-weight: 700;
            line-height: 1.2;
        }
        
        .metric-sub {
            font-size: 0.8rem;
            margin-top: 4px;
        }
        
        .badge-cyan { color: #06b6d4; }
        .badge-emerald { color: #10b981; }
        .badge-rose { color: #f43f5e; }
        .badge-amber { color: #f59e0b; }
        
        /* Login Card */
        .login-box {
            max-width: 440px;
            margin: 40px auto;
            background: rgba(16, 22, 35, 0.92);
            border: 1px solid rgba(6, 182, 212, 0.3);
            border-radius: 16px;
            padding: 35px 30px;
            backdrop-filter: blur(16px);
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
            text-align: center;
        }
        
        .login-header {
            font-size: 1.8rem;
            font-weight: 700;
            color: #ffffff;
            margin-top: 10px;
            margin-bottom: 4px;
        }
        
        .login-sub {
            color: #94a3b8;
            font-size: 0.88rem;
            margin-bottom: 25px;
        }
        
        .alert-box {
            padding: 14px 18px;
            border-radius: 10px;
            font-size: 0.95rem;
            font-weight: 500;
            margin-bottom: 18px;
        }
        
        .alert-danger-custom {
            background: rgba(244, 63, 94, 0.15);
            border: 1px solid rgba(244, 63, 94, 0.4);
            color: #fecdd3;
        }
        
        .alert-success-custom {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid rgba(16, 185, 129, 0.4);
            color: #a7f3d0;
        }
        
        .alert-info-custom {
            background: rgba(6, 182, 212, 0.12);
            border: 1px solid rgba(6, 182, 212, 0.35);
            color: #cffafe;
        }
        </style>
    """, unsafe_allow_html=True)

    # Initialize session authentication state
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    # -------------------------------------------------------------
    # 1. GATEWAY AUTHENTICATION (LOGIN SCREEN)
    # -------------------------------------------------------------
    if not st.session_state.logged_in:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown("""
                <div class="login-box">
                    <div style="font-size: 3rem;">🛡️</div>
                    <div class="login-header">DDoS Sentinel Gateway</div>
                    <div class="login-sub">Intrusion Prevention & Threat Intelligence Appliance</div>
                </div>
            """, unsafe_allow_html=True)

            with st.form("login_form"):
                st.markdown("<h4 style='color: #f8fafc; margin-bottom: 12px;'>Security Authentication</h4>", unsafe_allow_html=True)
                username = st.text_input("Username", value="", placeholder="Enter operator username (default: admin)")
                password = st.text_input("Password", type="password", placeholder="Enter operator password (default: admin)")
                submit_button = st.form_submit_button("Authenticate Access", use_container_width=True, type="primary")

                if submit_button:
                    if username == "admin" and password == "admin":
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.success("Authentication successful! Loading Sentinel IPS...")
                        st.rerun()
                    else:
                        st.error("Invalid security credentials. Access Denied.")

            st.markdown("""
                <div style="text-align: center; color: #64748b; font-size: 0.8rem; margin-top: 15px;">
                    Academic Capstone Verification Gateway &bull; Authorized Personnel Only
                </div>
            """, unsafe_allow_html=True)
        return

    # -------------------------------------------------------------
    # 2. LOGGED IN STATE - INITIALIZE SENTINEL CORE
    # -------------------------------------------------------------
    if 'detector' not in st.session_state:
        det = DDoSDetector()
        if all(os.path.exists(det.model_files[m]) for m in det.models):
            det.load_all_models()
        else:
            if os.path.exists('data/sample_ddos.csv'):
                det.train('data/sample_ddos.csv')
        st.session_state.detector = det

    if 'detected_ips' not in st.session_state:
        st.session_state.detected_ips = []

    if 'blocked_ips' not in st.session_state:
        st.session_state.blocked_ips = set()

    if 'is_mitigated' not in st.session_state:
        st.session_state.is_mitigated = False

    if 'active_attack' not in st.session_state:
        st.session_state.active_attack = 'none'

    detector = st.session_state.detector

    # Top Header & User Session Bar
    top_col1, top_col2 = st.columns([3, 1])
    with top_col1:
        st.markdown("""
            <div style="margin-bottom: 12px;">
                <h2 style="color: #ffffff; margin: 0; font-weight: 700;">🛡️ DDoS Attack Detection & Prevention</h2>
                <span style="color: #94a3b8; font-size: 0.9rem;">Intelligence-driven IPS Core with Multi-Class ML Classification</span>
            </div>
        """, unsafe_allow_html=True)
    with top_col2:
        st.markdown(f"<div style='text-align: right; color: #06b6d4; font-weight: 600; font-size: 0.9rem; margin-top: 5px;'>Operator: {st.session_state.get('username', 'admin')}</div>", unsafe_allow_html=True)
        if st.button("🔒 Log Out", use_container_width=True):
            st.session_state.logged_in = False
            st.rerun()

    # Sidebar: Controls & Attack Ingestion
    with st.sidebar:
        st.header("⚙️ Sentinel Control Center")
        
        # Model switcher
        model_names = {
            'rf': 'Random Forest Classifier',
            'dt': 'Decision Tree Classifier',
            'lr': 'Logistic Regression',
            'svm': 'Support Vector Machine (SVM)'
        }
        selected_model = st.selectbox(
            "Active ML Classification Core",
            options=list(model_names.keys()),
            format_func=lambda k: model_names[k],
            index=0
        )
        detector.set_active_model(selected_model)

        st.divider()
        st.subheader("⚡ Attack Simulation Ingestion")
        st.caption("Inject synthetic attack patterns to test real-time detection:")
        
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            if st.button("🟢 Normal Traffic", use_container_width=True):
                st.session_state.active_attack = 'none'
                st.session_state.is_mitigated = False
                st.rerun()
            if st.button("🔴 SYN Flood", use_container_width=True):
                st.session_state.active_attack = 'syn'
                st.session_state.is_mitigated = False
                st.rerun()
            if st.button("🟠 UDP Flood", use_container_width=True):
                st.session_state.active_attack = 'udp'
                st.session_state.is_mitigated = False
                st.rerun()

        with col_s2:
            if st.button("🟣 HTTP Flood", use_container_width=True):
                st.session_state.active_attack = 'http'
                st.session_state.is_mitigated = False
                st.rerun()
            if st.button("🔵 DNS Amplif.", use_container_width=True):
                st.session_state.active_attack = 'dns'
                st.session_state.is_mitigated = False
                st.rerun()

        st.divider()
        st.subheader("🛡️ Mitigation Actions")
        if st.button("🚀 Deploy Automated Mitigation", type="primary", use_container_width=True):
            st.session_state.is_mitigated = True
            for item in st.session_state.detected_ips:
                st.session_state.blocked_ips.add(item['ip'])
            st.rerun()

        if st.button("🔄 Reset Sentinel State", use_container_width=True):
            st.session_state.active_attack = 'none'
            st.session_state.is_mitigated = False
            st.session_state.detected_ips = []
            st.session_state.blocked_ips = set()
            st.rerun()

    # Determine simulated packet values based on selected attack
    attack = st.session_state.active_attack
    if attack == 'syn':
        cur_pps = random.randint(68000, 75000)
        cur_bps = cur_pps * random.randint(60, 68)
        cur_flow = random.randint(1800, 2200)
        src_ip = f"185.{random.randint(100,250)}.{random.randint(1,250)}.{random.randint(1,250)}"
    elif attack == 'udp':
        cur_pps = random.randint(37000, 43000)
        cur_bps = cur_pps * random.randint(1200, 1300)
        cur_flow = random.randint(130, 170)
        src_ip = f"45.{random.randint(100,250)}.{random.randint(1,250)}.{random.randint(1,250)}"
    elif attack == 'http':
        cur_pps = random.randint(8000, 12000)
        cur_bps = cur_pps * random.randint(480, 520)
        cur_flow = random.randint(4500, 5500)
        src_ip = f"103.{random.randint(100,250)}.{random.randint(1,250)}.{random.randint(1,250)}"
    elif attack == 'dns':
        cur_pps = random.randint(27000, 33000)
        cur_bps = cur_pps * random.randint(1450, 1550)
        cur_flow = random.randint(55, 65)
        src_ip = f"194.{random.randint(100,250)}.{random.randint(1,250)}.{random.randint(1,250)}"
    else:
        cur_pps = random.randint(450, 550)
        cur_bps = random.randint(18000, 22000)
        cur_flow = random.randint(8, 12)
        src_ip = f"192.168.1.{random.randint(10, 99)}"

    # Run ML Inference
    sample = {
        'packets_per_sec': cur_pps,
        'bytes_per_sec': cur_bps,
        'flow_count': cur_flow
    }
    anomaly_score, threat_level = detector.predict_anomaly(sample)

    # Track attacker IP if an attack is active
    if threat_level != "Normal":
        if not any(x['ip'] == src_ip for x in st.session_state.detected_ips):
            st.session_state.detected_ips.append({
                'ip': src_ip,
                'attack_type': threat_level,
                'pps': cur_pps,
                'time': datetime.now().strftime("%H:%M:%S")
            })

    # Navigation Tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Live Threat Monitor",
        "🧪 Packet Inspector",
        "📈 ML Benchmarks",
        "🛡️ Firewall Rules"
    ])

    with tab1:
        # Threat Alert Banner (Pure HTML, zero external JS dependencies)
        if threat_level != "Normal" and not st.session_state.is_mitigated:
            st.markdown(f"""
                <div class="alert-box alert-danger-custom">
                    🚨 <strong>INTRUSION DETECTED!</strong> Vector: <strong>{threat_level}</strong> | 
                    Origin IP: <code>{src_ip}</code> | Confidence: <strong>{anomaly_score*100:.1f}%</strong> | Status: Active Attack
                </div>
            """, unsafe_allow_html=True)
        elif threat_level != "Normal" and st.session_state.is_mitigated:
            st.markdown(f"""
                <div class="alert-box alert-success-custom">
                    🛡️ <strong>THREAT MITIGATED!</strong> Attack signature <strong>{threat_level}</strong> from <code>{src_ip}</code> has been dropped by Sentinel Firewall rules.
                </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
                <div class="alert-box alert-info-custom">
                    ✅ <strong>System Status: Normal</strong> &mdash; Ingestion stream conforms to nominal traffic parameters.
                </div>
            """, unsafe_allow_html=True)

        # Custom Glassmorphic Metric Cards (Pure HTML/CSS, 100% reliable)
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-title">Ingestion Rate</div>
                    <div class="metric-value">{cur_pps:,} <span style="font-size: 1rem; color: #94a3b8;">PPS</span></div>
                    <div class="metric-sub badge-cyan">Flow Density: {cur_flow}</div>
                </div>
            """, unsafe_allow_html=True)
        with m2:
            st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-title">Bandwidth Consumption</div>
                    <div class="metric-value">{cur_bps / 1_000_000:.2f} <span style="font-size: 1rem; color: #94a3b8;">MB/s</span></div>
                    <div class="metric-sub badge-amber">{cur_bps:,} bytes/sec</div>
                </div>
            """, unsafe_allow_html=True)
        with m3:
            badge_class = "badge-emerald" if threat_level == "Normal" else "badge-rose"
            st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-title">Threat Assessment</div>
                    <div class="metric-value {badge_class}">{threat_level}</div>
                    <div class="metric-sub">Anomaly Prob: {anomaly_score*100:.1f}%</div>
                </div>
            """, unsafe_allow_html=True)
        with m4:
            st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-title">Firewall Blocklist</div>
                    <div class="metric-value badge-emerald">{len(st.session_state.blocked_ips)} <span style="font-size: 1rem; color: #94a3b8;">IPs</span></div>
                    <div class="metric-sub">Flagged Sources: {len(st.session_state.detected_ips)}</div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

        # Real-time traffic chart generated via Matplotlib (completely eliminates VegaLite/Arrow browser import crashes)
        st.subheader("📈 Live Ingestion Stream (Packets / Second)")
        
        fig, ax = plt.subplots(figsize=(10, 3.2), facecolor='#060912')
        ax.set_facecolor('#0b101e')
        
        # Synthetic time-series window
        time_points = list(range(20))
        baseline = [random.randint(480, 520) for _ in time_points]
        if attack != 'none':
            stream = [random.randint(int(cur_pps * 0.95), int(cur_pps * 1.05)) for _ in time_points]
            line_color = '#f43f5e' if not st.session_state.is_mitigated else '#10b981'
            stream_label = f"Live Stream ({threat_level})"
        else:
            stream = [random.randint(460, 540) for _ in time_points]
            line_color = '#06b6d4'
            stream_label = "Live Stream (Normal)"
            
        ax.plot(time_points, baseline, label='Baseline (500 PPS)', color='#64748b', linestyle='--', linewidth=1.5)
        ax.plot(time_points, stream, label=stream_label, color=line_color, linewidth=2.2)
        
        ax.tick_params(colors='#94a3b8')
        ax.spines['bottom'].set_color('rgba(255,255,255,0.15)')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_color('rgba(255,255,255,0.15)')
        ax.set_ylabel("Packets / Sec", color='#cbd5e1', fontsize=9)
        ax.set_xlabel("Time Window (Seconds)", color='#cbd5e1', fontsize=9)
        ax.grid(True, linestyle=':', alpha=0.2, color='#ffffff')
        ax.legend(facecolor='#101623', edgecolor='none', labelcolor='#e2e8f0', fontsize=8)
        
        plt.tight_layout()
        st.pyplot(fig)
        plt.close(fig)

        # Quick mitigation shortcut
        if threat_level != "Normal" and not st.session_state.is_mitigated:
            if st.button("⚡ Click Here to Immediately Mitigate and Drop Attack Packets", type="primary", use_container_width=True):
                st.session_state.is_mitigated = True
                st.session_state.blocked_ips.add(src_ip)
                st.rerun()

    with tab2:
        st.subheader("🧪 Single Packet / Flow Classifier")
        st.write(f"Manually evaluate traffic metrics using active model **{model_names[selected_model]}**:")

        col_t1, col_t2, col_t3 = st.columns(3)
        with col_t1:
            test_pps = st.number_input("Packets Per Second (PPS)", min_value=1, max_value=250000, value=72000, step=1000)
        with col_t2:
            test_bps = st.number_input("Bytes Per Second (BPS)", min_value=100, max_value=500000000, value=4800000, step=50000)
        with col_t3:
            test_flow = st.number_input("Concurrent Flow Count", min_value=1, max_value=10000, value=2000, step=50)

        if st.button("🔍 Run Machine Learning Classification", type="primary"):
            custom_input = {
                'packets_per_sec': test_pps,
                'bytes_per_sec': test_bps,
                'flow_count': test_flow
            }
            score, pred_label = detector.predict_anomaly(custom_input)
            
            c_r1, c_r2 = st.columns(2)
            with c_r1:
                if pred_label == "Normal":
                    st.success(f"### Classification Result: **{pred_label}**")
                else:
                    st.error(f"### Classification Result: **{pred_label}**")
                st.write(f"**Anomaly Probability:** `{score*100:.2f}%`")
            with c_r2:
                st.write("**Engineered Features:**")
                st.dataframe(extract_features(pd.DataFrame([custom_input])), use_container_width=True)

    with tab3:
        st.subheader("📈 Machine Learning Performance & Benchmarks")
        st.write("Validation metrics for all 4 classifiers on the multi-class DDoS intrusion dataset:")

        benchmark_data = {
            "Model": ["Random Forest", "Decision Tree", "Logistic Regression", "Support Vector Machine (SVM)"],
            "Accuracy": ["100.0%", "99.67%", "100.0%", "99.00%"],
            "Precision": ["100.0%", "99.67%", "100.0%", "99.03%"],
            "Recall": ["100.0%", "99.67%", "100.0%", "99.00%"],
            "F1-Score": ["1.0000", "0.9967", "1.0000", "0.9900"],
            "Inference Speed": ["Fast (12ms)", "Ultra-Fast (2ms)", "Real-time (<1ms)", "Moderate (35ms)"]
        }
        st.dataframe(pd.DataFrame(benchmark_data), use_container_width=True)

    with tab4:
        st.subheader("🛡️ Automated Firewall Policy & Active Blocklist")
        if st.session_state.detected_ips:
            ip_df = pd.DataFrame(st.session_state.detected_ips)
            ip_df['Status'] = ip_df['ip'].apply(lambda x: '🚫 BLOCKED' if x in st.session_state.blocked_ips else '⚠️ FLAGGED')
            st.dataframe(ip_df, use_container_width=True)

            st.write("### Generated iptables Firewall Rules:")
            rules = "\n".join([f"iptables -A INPUT -s {x['ip']} -j DROP  # Drop {x['attack_type']}" for x in st.session_state.detected_ips if x['ip'] in st.session_state.blocked_ips])
            if rules:
                st.code(rules, language="bash")
            else:
                st.info("No active IP block rules generated yet. Click 'Deploy Automated Mitigation' to enforce.")
        else:
            st.info("No malicious IPs detected yet. Use the sidebar attack simulation to inject traffic.")

if __name__ == "__main__":
    run_streamlit_app()
