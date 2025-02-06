# app/routes.py
from flask import render_template, jsonify
from app import app
from analyser.sniffer import NetworkAnalyzer
from scapy.all import sniff
import threading

# analyzer instance
analyzer = NetworkAnalyzer(verbose=False)

# packet capture in a separate thread
capture_thread = threading.Thread(target=lambda: sniff(prn=analyzer.analyse_packets, store=False), daemon=True)
capture_thread.start()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    return jsonify(analyzer.get_current_stats())