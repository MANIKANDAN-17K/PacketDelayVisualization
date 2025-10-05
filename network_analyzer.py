#!/usr/bin/env python3
"""
Network Packet Analyzer Dashboard
Complete Single-File Implementation
OS-Safe for Ubuntu 22.04 with Python 3.10.12

Author: Network Analysis Team
Version: 1.0.0
"""

import dash
from dash import dcc, html, Input, Output, State, ALL
import plotly.graph_objs as go
import pandas as pd
import numpy as np
import base64
import io
import threading
import queue
import time
import json
from datetime import datetime
import subprocess
import os

# Try to import optional dependencies
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("⚠️  psutil not installed - system monitoring disabled")

try:
    import pyshark
    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False
    print("⚠️  pyshark not installed - PCAP support limited to tshark")

try:
    from scapy.all import sniff, IP, TCP, UDP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("⚠️  scapy not installed - live capture disabled")

# ============================================================================
# PACKET PROCESSOR CLASS - OS-SAFE BACKEND
# ============================================================================

class PacketProcessor:
    """OS-safe packet processing engine"""
    
    def __init__(self):
        self.capture_thread = None
        self.is_capturing = False
        self.packet_buffer = queue.Queue(maxsize=5000)  # Memory limit
        self.processed_packets = []
        self.packet_count = 0
        
    def process_pcap(self, filepath):
        """Process PCAP file safely"""
        try:
            if HAS_PYSHARK:
                return self._process_with_pyshark(filepath)
            else:
                return self._process_with_tshark(filepath)
        except Exception as e:
            print(f"Error processing PCAP: {e}")
            return pd.DataFrame()
    
    def _process_with_pyshark(self, filepath):
        """Process using pyshark library"""
        try:
            packets_data = []
            capture = pyshark.FileCapture(filepath, keep_packets=False)
            
            count = 0
            max_packets = 10000  # Prevent memory overflow
            
            for packet in capture:
                if count >= max_packets:
                    break
                    
                try:
                    packet_info = self._extract_packet_info_pyshark(packet)
                    if packet_info:
                        packets_data.append(packet_info)
                    count += 1
                except Exception:
                    continue
            
            capture.close()
            
            if packets_data:
                df = pd.DataFrame(packets_data)
                return self.calculate_metrics(df)
            return pd.DataFrame()
            
        except Exception as e:
            print(f"Pyshark error: {e}")
            return pd.DataFrame()
    
    def _process_with_tshark(self, filepath):
        """Fallback to tshark command-line"""
        try:
            cmd = [
                'tshark', '-r', filepath,
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time_relative',
                '-e', 'ip.proto',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'frame.len',
                '-E', 'header=y',
                '-E', 'separator=,',
                '-c', '10000'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                df = pd.read_csv(io.StringIO(result.stdout))
                return self._process_tshark_output(df)
            else:
                print(f"tshark error: {result.stderr}")
                return pd.DataFrame()
                
        except FileNotFoundError:
            print("❌ tshark not found. Install: sudo apt-get install tshark")
            return pd.DataFrame()
        except Exception as e:
            print(f"Error: {e}")
            return pd.DataFrame()
    
    def _process_tshark_output(self, df):
        """Convert tshark output to our format"""
        processed = pd.DataFrame()
        
        if 'frame.time_relative' in df.columns:
            processed['Timestamp'] = pd.to_numeric(df['frame.time_relative'], errors='coerce')
        
        if 'ip.proto' in df.columns:
            protocol_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}
            processed['Protocol'] = df['ip.proto'].map(protocol_map).fillna('Other')
        
        processed['Source'] = df.get('ip.src', '')
        processed['Dest'] = df.get('ip.dst', '')
        processed['Length'] = pd.to_numeric(df.get('frame.len', 0), errors='coerce')
        
        # Get port info
        if 'tcp.dstport' in df.columns:
            processed['DstPort'] = pd.to_numeric(df['tcp.dstport'], errors='coerce')
        elif 'udp.dstport' in df.columns:
            processed['DstPort'] = pd.to_numeric(df['udp.dstport'], errors='coerce')
        
        return self.calculate_metrics(processed)
    
    def _extract_packet_info_pyshark(self, packet):
        """Extract info from pyshark packet"""
        try:
            info = {
                'Timestamp': float(packet.sniff_timestamp),
                'Protocol': packet.highest_layer,
                'Length': int(packet.length)
            }
            
            if hasattr(packet, 'ip'):
                info['Source'] = packet.ip.src
                info['Dest'] = packet.ip.dst
            
            if hasattr(packet, 'tcp'):
                info['SrcPort'] = int(packet.tcp.srcport)
                info['DstPort'] = int(packet.tcp.dstport)
                info['Protocol'] = 'TCP'
            elif hasattr(packet, 'udp'):
                info['SrcPort'] = int(packet.udp.srcport)
                info['DstPort'] = int(packet.udp.dstport)
                info['Protocol'] = 'UDP'
            
            return info
        except Exception:
            return None
    
    def calculate_metrics(self, df):
        """Calculate packet delay metrics - Memory efficient"""
        if df.empty or 'Timestamp' not in df.columns:
            return df
        
        # Sort by timestamp
        df = df.sort_values('Timestamp').reset_index(drop=True)
        
        # Calculate inter-packet delay (milliseconds)
        df['Delay'] = df['Timestamp'].diff() * 1000
        df['Delay'] = df['Delay'].fillna(0)
        
        # Calculate jitter
        df['Jitter'] = df['Delay'].diff().abs()
        df['Jitter'] = df['Jitter'].fillna(0)
        
        # Map ports to applications
        if 'DstPort' in df.columns:
            df['App'] = df['DstPort'].apply(self._port_to_app)
        else:
            df['App'] = 'Unknown'
        
        return df
    
    def _port_to_app(self, port):
        """Map ports to application names"""
        if pd.isna(port):
            return 'Unknown'
        
        port = int(port)
        port_map = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
            25: 'SMTP', 53: 'DNS', 3478: 'WhatsApp', 5222: 'WhatsApp',
            5223: 'WhatsApp', 8080: 'HTTP-Alt', 3389: 'RDP',
            5060: 'SIP', 5061: 'SIP-TLS', 1935: 'RTMP'
        }
        return port_map.get(port, 'Other')
    
    def start_live_capture(self, interface='any'):
        """Start live capture - OS safe with limits"""
        if self.is_capturing:
            return
        
        if not HAS_SCAPY and not HAS_PYSHARK:
            raise Exception("No capture library available. Install scapy or pyshark")
        
        # Check system resources
        can_capture, msg = self.check_system_resources()
        if not can_capture:
            raise Exception(msg)
        
        self.is_capturing = True
        self.processed_packets = []
        self.packet_count = 0
        
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(interface,),
            daemon=True  # Won't block program exit
        )
        self.capture_thread.start()
    
    def _capture_loop(self, interface):
        """Main capture loop - runs in separate thread"""
        try:
            if HAS_SCAPY:
                self._capture_with_scapy(interface)
            elif HAS_PYSHARK:
                self._capture_with_pyshark(interface)
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            self.is_capturing = False
    
    def _capture_with_scapy(self, interface):
        """Capture using scapy"""
        def process_packet(packet):
            if not self.is_capturing:
                return True  # Stop sniffing
            
            try:
                packet_info = {
                    'Timestamp': time.time(),
                    'Protocol': 'Other',
                    'Length': len(packet)
                }
                
                if IP in packet:
                    packet_info['Source'] = packet[IP].src
                    packet_info['Dest'] = packet[IP].dst
                
                if TCP in packet:
                    packet_info['Protocol'] = 'TCP'
                    packet_info['SrcPort'] = packet[TCP].sport
                    packet_info['DstPort'] = packet[TCP].dport
                elif UDP in packet:
                    packet_info['Protocol'] = 'UDP'
                    packet_info['SrcPort'] = packet[UDP].sport
                    packet_info['DstPort'] = packet[UDP].dport
                
                # Add to buffer (non-blocking)
                try:
                    self.packet_buffer.put_nowait(packet_info)
                    self.packet_count += 1
                    
                    # Cleanup every 1000 packets
                    if self.packet_count % 1000 == 0:
                        self._cleanup_old_packets()
                        
                except queue.Full:
                    # Buffer full - remove oldest
                    try:
                        self.packet_buffer.get_nowait()
                        self.packet_buffer.put_nowait(packet_info)
                    except:
                        pass
                
            except Exception as e:
                print(f"Packet process error: {e}")
            
            # Small delay to prevent CPU overload
            time.sleep(0.001)
        
        # Start sniffing
        sniff(prn=process_packet, store=False, stop_filter=lambda x: not self.is_capturing)
    
    def _capture_with_pyshark(self, interface):
        """Capture using pyshark"""
        try:
            capture = pyshark.LiveCapture(interface=interface, bpf_filter='ip')
            
            for packet in capture.sniff_continuously():
                if not self.is_capturing:
                    break
                
                packet_info = self._extract_packet_info_pyshark(packet)
                if packet_info:
                    try:
                        self.packet_buffer.put_nowait(packet_info)
                        self.packet_count += 1
                        
                        if self.packet_count % 1000 == 0:
                            self._cleanup_old_packets()
                            
                    except queue.Full:
                        try:
                            self.packet_buffer.get_nowait()
                            self.packet_buffer.put_nowait(packet_info)
                        except:
                            pass
                
                time.sleep(0.001)
                
        except Exception as e:
            print(f"Pyshark capture error: {e}")
    
    def _cleanup_old_packets(self):
        """Remove old packets to free memory"""
        try:
            if len(self.processed_packets) > 500:
                self.processed_packets = self.processed_packets[-500:]
        except:
            pass
    
    def stop_live_capture(self):
        """Stop capture gracefully"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
    
    def get_live_data(self):
        """Get processed live packets"""
        packets = []
        
        # Drain the queue
        while not self.packet_buffer.empty():
            try:
                packets.append(self.packet_buffer.get_nowait())
            except queue.Empty:
                break
        
        if packets:
            self.processed_packets.extend(packets)
            # Keep only recent packets
            self.processed_packets = self.processed_packets[-1000:]
        
        if self.processed_packets:
            df = pd.DataFrame(self.processed_packets)
            return self.calculate_metrics(df)
        
        return pd.DataFrame()
    
    def check_system_resources(self):
        """Check if safe to capture - prevents OS crashes"""
        if not HAS_PSUTIL:
            return True, "OK"
        
        try:
            memory = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=1)
            
            if memory.percent > 90:
                return False, "Memory usage too high (>90%)"
            if cpu > 90:
                return False, "CPU usage too high (>90%)"
            
            return True, "OK"
        except:
            return True, "OK"

# ============================================================================
# GLOBAL STATE
# ============================================================================

processor = PacketProcessor()

class AppState:
    def __init__(self):
        self.mode = "previous"
        self.selected_app = "All"
        self.selected_protocol = "General"

app_state = AppState()

# Color scheme
COLORS = {
    'background': '#1e1e1e',
    'card': '#2d2d2d',
    'text': '#ffffff',
    'accent': '#00d4ff',
    'success': '#00ff88',
    'warning': '#ffaa00',
    'error': '#ff4444'
}

# ============================================================================
# DASH APPLICATION
# ============================================================================

app = dash.Dash(__name__, suppress_callback_exceptions=True)
app.title = "Network Packet Analyzer"

# Layout
app.layout = html.Div([
    dcc.Store(id='data-store', data={}),
    dcc.Interval(id='live-update', interval=2000, disabled=True),
    
    # TOP ROW - Header
    html.Div([
        # Logo
        html.Div([
            html.Div([
                html.Div("🔵", style={'fontSize': '40px'}),
                html.Div("NetAnalyzer", style={'fontSize': '12px', 'marginTop': '5px'})
            ], style={'textAlign': 'center', 'display': 'flex', 'flexDirection': 'column', 'justifyContent': 'center', 'alignItems': 'center', 'height': '100%'})
        ], style={'width': '10%', 'height': '100%', 'display': 'flex', 'alignItems': 'center', 'justifyContent': 'center'}),
        
        # Menu Bar
        html.Div([
            html.Div([
                html.Button('File', className='menu-btn'),
                html.Button('Edit', className='menu-btn'),
                html.Button('View', className='menu-btn'),
                html.Button('Analysis', className='menu-btn'),
                html.Button('Statistics', className='menu-btn'),
                html.Button('Tools', className='menu-btn'),
                html.Button('Help', className='menu-btn'),
            ], style={'display': 'flex', 'gap': '10px', 'justifyContent': 'center', 'alignItems': 'center', 'height': '100%'})
        ], style={'width': '80%', 'height': '100%', 'display': 'flex', 'alignItems': 'center'}),
        
        # Mode Selection
        html.Div([
            html.Button('Select Mode ▼', id='mode-btn', style={'width': '140px', 'height': '40px'}),
            html.Div([
                html.Button('Previous Delay', id='prev-mode-btn', className='mode-option'),
                html.Button('Live Delay', id='live-mode-btn', className='mode-option'),
            ], id='mode-dropdown', style={'display': 'none', 'position': 'absolute', 'right': '10px', 'top': '60px',
                                         'background': COLORS['card'], 'border': '1px solid ' + COLORS['accent'],
                                         'borderRadius': '5px', 'zIndex': '1000', 'padding': '5px'}),
        ], style={'width': '10%', 'height': '100%', 'display': 'flex', 'alignItems': 'center', 'justifyContent': 'center', 'position': 'relative'}),
    ], style={'height': '15vh', 'background': COLORS['card'], 'borderBottom': '2px solid ' + COLORS['accent'], 'display': 'flex'}),
    
    # Mode Controls
    html.Div([
        # Previous mode controls
        html.Div([
            dcc.Upload(
                id='upload-data',
                children=html.Button('📁 Select File (PCAP/CSV)', style={'width': '220px', 'height': '40px', 'fontSize': '14px'}),
                style={'display': 'inline-block', 'margin': '10px'}
            ),
            html.Div(id='upload-status', style={'display': 'inline-block', 'marginLeft': '10px'})
        ], id='prev-controls', style={'display': 'none', 'textAlign': 'center'}),
        
        # Live mode controls
        html.Div([
            html.Button('▶ Start Capture', id='start-btn', style={'width': '150px', 'height': '40px', 'background': COLORS['success'], 'margin': '5px', 'border': 'none', 'color': 'white', 'borderRadius': '5px', 'cursor': 'pointer'}),
            html.Button('■ Stop Capture', id='stop-btn', style={'width': '150px', 'height': '40px', 'background': COLORS['error'], 'margin': '5px', 'border': 'none', 'color': 'white', 'borderRadius': '5px', 'cursor': 'pointer'}),
            html.Div(id='capture-status', style={'display': 'inline-block', 'marginLeft': '10px'})
        ], id='live-controls', style={'display': 'none', 'textAlign': 'center'}),
    ], style={'background': COLORS['background'], 'padding': '10px'}),
    
    # MIDDLE ROW - Main Content
    html.Div([
        # Left - Applications
        html.Div([
            html.H4('Applications', style={'textAlign': 'center', 'borderBottom': '1px solid ' + COLORS['accent'], 'padding': '10px', 'margin': '0'}),
            html.Div(id='app-list', style={'overflowY': 'auto', 'height': 'calc(70vh - 60px)', 'padding': '5px'})
        ], style={'width': '20%', 'background': COLORS['card'], 'height': '70vh', 'borderRight': '1px solid ' + COLORS['accent']}),
        
        # Middle - Graph & Table
        html.Div([
            # Graph
            html.Div([
                dcc.Graph(id='delay-graph', style={'height': '100%'}, config={'displayModeBar': False})
            ], style={'height': '50%'}),
            
            # Packet Table
            html.Div([
                html.H5('Packet Type Distribution', style={'textAlign': 'center', 'margin': '10px 0', 'color': COLORS['accent']}),
                html.Div(id='packet-table', style={'overflowY': 'auto', 'height': 'calc(35vh - 50px)', 'padding': '10px'})
            ], style={'height': '50%', 'background': COLORS['card'], 'borderTop': '1px solid ' + COLORS['accent']}),
        ], style={'width': '60%', 'height': '70vh'}),
        
        # Right - Filters & Stats
        html.Div([
            # Filters
            html.Div([
                html.H5('Protocol Filter', style={'textAlign': 'center', 'borderBottom': '1px solid ' + COLORS['accent'], 'padding': '10px', 'margin': '0'}),
                html.Div([
                    html.Button('General', id='filter-general', className='filter-btn active', style={'width': '90%', 'margin': '5px auto', 'display': 'block'}),
                    html.Button('TCP', id='filter-tcp', className='filter-btn', style={'width': '90%', 'margin': '5px auto', 'display': 'block'}),
                    html.Button('UDP', id='filter-udp', className='filter-btn', style={'width': '90%', 'margin': '5px auto', 'display': 'block'}),
                    html.Button('ICMP', id='filter-icmp', className='filter-btn', style={'width': '90%', 'margin': '5px auto', 'display': 'block'}),
                    html.Button('HTTP', id='filter-http', className='filter-btn', style={'width': '90%', 'margin': '5px auto', 'display': 'block'}),
                ], style={'padding': '10px'}),
            ]),
            
            # Statistics
            html.Div([
                html.H5('Statistics', style={'textAlign': 'center', 'borderTop': '1px solid ' + COLORS['accent'], 'borderBottom': '1px solid ' + COLORS['accent'], 'padding': '10px', 'margin': '20px 0 0 0'}),
                html.Div(id='protocol-stats', style={'padding': '10px', 'overflowY': 'auto', 'maxHeight': '300px'})
            ]),
        ], style={'width': '20%', 'background': COLORS['card'], 'height': '70vh', 'borderLeft': '1px solid ' + COLORS['accent']}),
    ], style={'background': COLORS['background'], 'display': 'flex'}),
    
    # BOTTOM ROW - Footer
    html.Div([
        # Packet Summary
        html.Div([
            html.H5('Packet Summary', style={'margin': '0 0 10px 0', 'color': COLORS['accent']}),
            html.Div(id='packet-summary')
        ], style={'width': '25%', 'borderRight': '1px solid ' + COLORS['accent'], 'padding': '15px'}),
        
        # Additional Metrics
        html.Div([
            html.H5('Metrics', style={'margin': '0 0 10px 0', 'color': COLORS['accent'], 'textAlign': 'center'}),
            html.Div(id='additional-metrics')
        ], style={'width': '50%', 'borderRight': '1px solid ' + COLORS['accent'], 'padding': '15px'}),
        
        # Extra Features
        html.Div([
            html.Button('📥 Export CSV', id='export-btn', className='action-btn', style={'width': '90%', 'margin': '5px auto', 'display': 'block'}),
            html.Button('🔄 Reset', id='reset-btn', className='action-btn', style={'width': '90%', 'margin': '5px auto', 'display': 'block'}),
            html.Button('❓ Help', id='help-btn', className='action-btn', style={'width': '90%', 'margin': '5px auto', 'display': 'block'}),
            dcc.Download(id='download-data')
        ], style={'width': '25%', 'textAlign': 'center', 'padding': '15px'}),
    ], style={'height': '15vh', 'background': COLORS['card'], 'borderTop': '2px solid ' + COLORS['accent'], 'display': 'flex'}),
    
], style={'background': COLORS['background'], 'color': COLORS['text'], 'fontFamily': 'Arial, sans-serif', 'minHeight': '100vh', 'margin': '0', 'padding': '0'})

# CSS Styling
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            * { box-sizing: border-box; }
            body { margin: 0; padding: 0; }
            .menu-btn, .filter-btn, .action-btn, .mode-option {
                background: #3d3d3d;
                color: white;
                border: 1px solid #00d4ff;
                padding: 8px 15px;
                cursor: pointer;
                border-radius: 5px;
                margin: 5px;
                font-size: 13px;
            }
            .menu-btn:hover, .filter-btn:hover, .action-btn:hover, .mode-option:hover {
                background: #00d4ff;
                color: #1e1e1e;
                transform: translateY(-1px);
                box-shadow: 0 2px 8px rgba(0, 212, 255, 0.3);
            }
            .filter-btn.active {
                background: #00d4ff;
                color: #1e1e1e;
                font-weight: bold;
            }
            .app-item {
                padding: 10px;
                margin: 5px;
                background: #3d3d3d;
                border-radius: 5px;
                cursor: pointer;
                border: 1px solid transparent;
                transition: all 0.2s;
            }
            .app-item:hover { 
                border-color: #00d4ff;
                transform: translateX(5px);
            }
            .app-item.selected { 
                background: #00d4ff;
                color: #1e1e1e;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

# ============================================================================
# CALLBACKS
# ============================================================================

# Toggle mode dropdown
@app.callback(
    Output('mode-dropdown', 'style'),
    Input('mode-btn', 'n_clicks'),
    State('mode-dropdown', 'style'),
    prevent_initial_call=True
)
def toggle_mode_dropdown(n, current_style):
    if current_style.get('display') == 'none':
        return {**current_style, 'display': 'block'}
    return {**current_style, 'display': 'none'}

# Select mode
@app.callback(
    [Output('prev-controls', 'style'),
     Output('live-controls', 'style'),
     Output('mode-btn', 'children')],
    [Input('prev-mode-btn', 'n_clicks'),
     Input('live-mode-btn', 'n_clicks')],
    prevent_initial_call=True
)
def select_mode(prev_clicks, live_clicks):
    from dash import callback_context
    
    if not callback_context.triggered:
        return {'display': 'none'}, {'display': 'none'}, 'Select Mode ▼'
    
    button_id = callback_context.triggered[0]['prop_id'].split('.')[0]
    
    if button_id == 'prev-mode-btn':
        app_state.mode = 'previous'
        return {'display': 'block', 'textAlign': 'center'}, {'display': 'none'}, 'Previous Delay ▼'
    else:
        app_state.mode = 'live'
        return {'display': 'none'}, {'display': 'block', 'textAlign': 'center'}, 'Live Delay ▼'

# Upload file
@app.callback(
    [Output('data-store', 'data'),
     Output('upload-status', 'children')],
    Input('upload-data', 'contents'),
    State('upload-data', 'filename'),
    prevent_initial_call=True
)
def upload_file(contents, filename):
    if contents is None:
        return {}, ''
    
    try:
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        
        if filename.endswith('.csv'):
            df = pd.read_csv(io.StringIO(decoded.decode('utf-8')))
            df = processor.calculate_metrics(df)
        elif filename.endswith('.pcap'):
            temp_path = f'/tmp/{filename}'
            with open(temp_path, 'wb') as f:
                f.write(decoded)
            df = processor.process_pcap(temp_path)
            # Clean up
            try:
                os.remove(temp_path)
            except:
                pass
        else:
            return {}, html.Div('❌ Unsupported file type', style={'color': COLORS['error']})
        
        if df.empty:
            return {}, html.Div('❌ No data parsed', style={'color': COLORS['error']})
        
        return {'data': df.to_dict('records'), 'filename': filename}, html.Div(f'✓ Loaded {filename} ({len(df)} packets)', style={'color': COLORS['success']})
    except Exception as e:
        return {}, html.Div(f'❌ Error: {str(e)}', style={'color': COLORS['error']})

# Control live capture
@app.callback(
    [Output('capture-status', 'children'),
     Output('live-update', 'disabled')],
    [Input('start-btn', 'n_clicks'),
     Input('stop-btn', 'n_clicks')],
    prevent_initial_call=True
)
def control_live_capture(start_clicks, stop_clicks):
    from dash import callback_context
    
    if not callback_context.triggered:
        return '', True
    
    button_id = callback_context.triggered[0]['prop_id'].split('.')[0]
    
    if button_id == 'start-btn':
        can_capture, msg = processor.check_system_resources()
        if not can_capture:
            return html.Div(f'❌ {msg}', style={'color': COLORS['error']}), True
        
        try:
            processor.start_live_capture()
            return html.Div('● Recording...', style={'color': COLORS['success'], 'fontWeight': 'bold'}), False
        except Exception as e:
            return html.Div(f'❌ Error: {str(e)}', style={'color': COLORS['error']}), True
    else:
        processor.stop_live_capture()
        return html.Div('■ Stopped', style={'color': COLORS['warning'], 'fontWeight': 'bold'}), True

# Update live data
@app.callback(
    Output('data-store', 'data', allow_duplicate=True),
    Input('live-update', 'n_intervals'),
    State('data-store', 'data'),
    prevent_initial_call=True
)
def update_live_data(n, current_data):
    if processor.is_capturing:
        df = processor.get_live_data()
        if not df.empty:
            return {'data': df.to_dict('records'), 'live': True}
    return current_data

# Update app list
@app.callback(
    Output('app-list', 'children'),
    Input('data-store', 'data')
)
def update_app_list(data):
    if not data or 'data' not in data:
        return html.Div('No data loaded', style={'padding': '10px', 'textAlign': 'center', 'color': '#888'})
    
    df = pd.DataFrame(data['data'])
    apps = ['All'] + (sorted(df['App'].unique().tolist()) if 'App' in df.columns else [])
    
    return [
        html.Div(
            app,
            id={'type': 'app-item', 'index': app},
            className='app-item' + (' selected' if app == app_state.selected_app else ''),
            n_clicks=0
        )
        for app in apps
    ]

# Update delay graph
@app.callback(
    Output('delay-graph', 'figure'),
    [Input('data-store', 'data'),
     Input({'type': 'app-item', 'index': ALL}, 'n_clicks'),
     Input('filter-general', 'n_clicks'),
     Input('filter-tcp', 'n_clicks'),
     Input('filter-udp', 'n_clicks'),
     Input('filter-icmp', 'n_clicks'),
     Input('filter-http', 'n_clicks')],
    [State({'type': 'app-item', 'index': ALL}, 'id')]
)
def update_delay_graph(data, app_clicks, gen, tcp, udp, icmp, http, app_ids):
    from dash import callback_context
    
    # Determine selected app
    if callback_context.triggered:
        trigger = callback_context.triggered[0]
        if 'app-item' in trigger['prop_id']:
            try:
                prop_id = json.loads(trigger['prop_id'].split('.')[0])
                app_state.selected_app = prop_id['index']
            except:
                pass
    
    # Determine selected protocol
    protocol_map = {
        'filter-general': 'General',
        'filter-tcp': 'TCP',
        'filter-udp': 'UDP',
        'filter-icmp': 'ICMP',
        'filter-http': 'HTTP'
    }
    
    if callback_context.triggered:
        trigger_id = callback_context.triggered[0]['prop_id'].split('.')[0]
        if trigger_id in protocol_map:
            app_state.selected_protocol = protocol_map[trigger_id]
    
    # Create empty graph if no data
    if not data or 'data' not in data:
        fig = go.Figure()
        fig.update_layout(
            title='Packet Delay Analysis - No Data',
            xaxis_title='Packet Index',
            yaxis_title='Delay (ms)',
            template='plotly_dark',
            paper_bgcolor=COLORS['background'],
            plot_bgcolor=COLORS['card'],
            font=dict(color=COLORS['text'])
        )
        return fig
    
    df = pd.DataFrame(data['data'])
    
    # Apply filters
    filtered_df = df.copy()
    
    if app_state.selected_app != 'All' and 'App' in filtered_df.columns:
        filtered_df = filtered_df[filtered_df['App'] == app_state.selected_app]
    
    if app_state.selected_protocol != 'General' and 'Protocol' in filtered_df.columns:
        filtered_df = filtered_df[filtered_df['Protocol'].str.upper() == app_state.selected_protocol.upper()]
    
    # Create graph
    fig = go.Figure()
    
    if 'Delay' in filtered_df.columns and len(filtered_df) > 0:
        # Limit points for performance
        if len(filtered_df) > 2000:
            step = len(filtered_df) // 2000
            plot_df = filtered_df.iloc[::step]
        else:
            plot_df = filtered_df
        
        fig.add_trace(go.Scatter(
            x=plot_df.index,
            y=plot_df['Delay'],
            mode='lines+markers',
            name='Delay',
            line=dict(color=COLORS['accent'], width=2),
            marker=dict(size=4, color=COLORS['accent']),
            hovertemplate='<b>Packet:</b> %{x}<br><b>Delay:</b> %{y:.2f} ms<extra></extra>'
        ))
        
        # Add threshold line at average
        avg_delay = plot_df['Delay'].mean()
        fig.add_hline(y=avg_delay, line_dash="dash", line_color=COLORS['warning'], 
                     annotation_text=f"Avg: {avg_delay:.2f} ms", annotation_position="right")
    
    fig.update_layout(
        title=f'Packet Delay - {app_state.selected_app} ({app_state.selected_protocol})',
        xaxis_title='Packet Index',
        yaxis_title='Delay (ms)',
        template='plotly_dark',
        paper_bgcolor=COLORS['background'],
        plot_bgcolor=COLORS['card'],
        font=dict(color=COLORS['text']),
        hovermode='closest',
        showlegend=False
    )
    
    return fig

# Update packet table
@app.callback(
    Output('packet-table', 'children'),
    Input('data-store', 'data')
)
def update_packet_table(data):
    if not data or 'data' not in data:
        return html.Div('No data', style={'textAlign': 'center', 'color': '#888', 'padding': '20px'})
    
    df = pd.DataFrame(data['data'])
    
    if 'Protocol' not in df.columns:
        return html.Div('No protocol data', style={'textAlign': 'center', 'color': '#888'})
    
    protocol_counts = df['Protocol'].value_counts().reset_index()
    protocol_counts.columns = ['Protocol', 'Count']
    protocol_counts['Percentage'] = (protocol_counts['Count'] / protocol_counts['Count'].sum() * 100).round(1)
    
    return html.Table([
        html.Thead(
            html.Tr([
                html.Th('Protocol', style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid ' + COLORS['accent'], 'color': COLORS['accent']}),
                html.Th('Count', style={'padding': '12px', 'textAlign': 'right', 'borderBottom': '2px solid ' + COLORS['accent'], 'color': COLORS['accent']}),
                html.Th('%', style={'padding': '12px', 'textAlign': 'right', 'borderBottom': '2px solid ' + COLORS['accent'], 'color': COLORS['accent']}),
            ])
        ),
        html.Tbody([
            html.Tr([
                html.Td(row['Protocol'], style={'padding': '10px', 'borderBottom': '1px solid #3d3d3d'}),
                html.Td(row['Count'], style={'padding': '10px', 'textAlign': 'right', 'borderBottom': '1px solid #3d3d3d', 'color': COLORS['success']}),
                html.Td(f"{row['Percentage']}%", style={'padding': '10px', 'textAlign': 'right', 'borderBottom': '1px solid #3d3d3d', 'color': COLORS['warning']}),
            ], style={'transition': 'background 0.2s', ':hover': {'background': '#3d3d3d'}})
            for _, row in protocol_counts.iterrows()
        ])
    ], style={'width': '100%', 'borderCollapse': 'collapse'})

# Update protocol stats
@app.callback(
    Output('protocol-stats', 'children'),
    Input('data-store', 'data')
)
def update_protocol_stats(data):
    if not data or 'data' not in data:
        return html.Div('No data', style={'textAlign': 'center', 'color': '#888'})
    
    df = pd.DataFrame(data['data'])
    
    if 'Delay' not in df.columns or len(df) == 0:
        return html.Div('No metrics', style={'textAlign': 'center', 'color': '#888'})
    
    stats = []
    
    # Delay statistics
    stats.append(html.Div([
        html.Div('Average Delay', style={'color': '#888', 'fontSize': '12px'}),
        html.Div(f"{df['Delay'].mean():.2f} ms", style={'color': COLORS['accent'], 'fontSize': '18px', 'fontWeight': 'bold'})
    ], style={'padding': '10px', 'borderBottom': '1px solid #3d3d3d'}))
    
    stats.append(html.Div([
        html.Div('Max Delay', style={'color': '#888', 'fontSize': '12px'}),
        html.Div(f"{df['Delay'].max():.2f} ms", style={'color': COLORS['error'], 'fontSize': '18px', 'fontWeight': 'bold'})
    ], style={'padding': '10px', 'borderBottom': '1px solid #3d3d3d'}))
    
    stats.append(html.Div([
        html.Div('Min Delay', style={'color': '#888', 'fontSize': '12px'}),
        html.Div(f"{df['Delay'].min():.2f} ms", style={'color': COLORS['success'], 'fontSize': '18px', 'fontWeight': 'bold'})
    ], style={'padding': '10px', 'borderBottom': '1px solid #3d3d3d'}))
    
    stats.append(html.Div([
        html.Div('Std Deviation', style={'color': '#888', 'fontSize': '12px'}),
        html.Div(f"{df['Delay'].std():.2f} ms", style={'color': COLORS['warning'], 'fontSize': '18px', 'fontWeight': 'bold'})
    ], style={'padding': '10px', 'borderBottom': '1px solid #3d3d3d'}))
    
    if 'Jitter' in df.columns:
        stats.append(html.Div([
            html.Div('Average Jitter', style={'color': '#888', 'fontSize': '12px'}),
            html.Div(f"{df['Jitter'].mean():.2f} ms", style={'color': COLORS['warning'], 'fontSize': '18px', 'fontWeight': 'bold'})
        ], style={'padding': '10px', 'borderBottom': '1px solid #3d3d3d'}))
    
    return html.Div(stats)

# Update packet summary
@app.callback(
    Output('packet-summary', 'children'),
    Input('data-store', 'data')
)
def update_packet_summary(data):
    if not data or 'data' not in data:
        return html.Div('No packets', style={'textAlign': 'center', 'color': '#888'})
    
    df = pd.DataFrame(data['data'])
    total = len(df)
    
    return html.Div([
        html.Div([
            html.Span('Total Packets', style={'color': '#888', 'display': 'block', 'fontSize': '12px'}),
            html.Strong(str(total), style={'color': COLORS['accent'], 'fontSize': '24px'})
        ], style={'marginBottom': '10px'}),
        html.Div([
            html.Span('Received', style={'color': '#888', 'display': 'block', 'fontSize': '12px'}),
            html.Strong(str(total), style={'color': COLORS['success'], 'fontSize': '20px'})
        ], style={'marginBottom': '10px'}),
        html.Div([
            html.Span('Lost', style={'color': '#888', 'display': 'block', 'fontSize': '12px'}),
            html.Strong('0', style={'color': COLORS['error'], 'fontSize': '20px'})
        ])
    ])

# Update additional metrics
@app.callback(
    Output('additional-metrics', 'children'),
    Input('data-store', 'data')
)
def update_additional_metrics(data):
    if not data or 'data' not in data:
        return html.Div('No data', style={'textAlign': 'center', 'color': '#888'})
    
    df = pd.DataFrame(data['data'])
    
    metrics = []
    
    if 'Delay' in df.columns and len(df) > 0:
        metrics.append(html.Div([
            html.Div('Average Delay', style={'fontSize': '12px', 'color': '#888'}),
            html.Div(f"{df['Delay'].mean():.2f} ms", style={'fontSize': '18px', 'color': COLORS['success'], 'fontWeight': 'bold'})
        ], style={'display': 'inline-block', 'margin': '0 20px', 'textAlign': 'center'}))
    
    if 'Jitter' in df.columns and len(df) > 0:
        metrics.append(html.Div([
            html.Div('Jitter', style={'fontSize': '12px', 'color': '#888'}),
            html.Div(f"{df['Jitter'].mean():.2f} ms", style={'fontSize': '18px', 'color': COLORS['warning'], 'fontWeight': 'bold'})
        ], style={'display': 'inline-block', 'margin': '0 20px', 'textAlign': 'center'}))
    
    if 'Length' in df.columns and len(df) > 0:
        total_bytes = df['Length'].sum()
        if total_bytes > 1024 * 1024:
            data_str = f"{total_bytes / (1024 * 1024):.2f} MB"
        elif total_bytes > 1024:
            data_str = f"{total_bytes / 1024:.2f} KB"
        else:
            data_str = f"{total_bytes} B"
        
        metrics.append(html.Div([
            html.Div('Total Data', style={'fontSize': '12px', 'color': '#888'}),
            html.Div(data_str, style={'fontSize': '18px', 'color': COLORS['accent'], 'fontWeight': 'bold'})
        ], style={'display': 'inline-block', 'margin': '0 20px', 'textAlign': 'center'}))
    
    if 'Timestamp' in df.columns and len(df) > 1:
        duration = df['Timestamp'].max() - df['Timestamp'].min()
        metrics.append(html.Div([
            html.Div('Duration', style={'fontSize': '12px', 'color': '#888'}),
            html.Div(f"{duration:.2f} s", style={'fontSize': '18px', 'color': COLORS['accent'], 'fontWeight': 'bold'})
        ], style={'display': 'inline-block', 'margin': '0 20px', 'textAlign': 'center'}))
    
    return html.Div(metrics, style={'display': 'flex', 'justifyContent': 'space-around', 'alignItems': 'center', 'height': '100%', 'flexWrap': 'wrap'})

# Export data
@app.callback(
    Output('download-data', 'data'),
    Input('export-btn', 'n_clicks'),
    State('data-store', 'data'),
    prevent_initial_call=True
)
def export_data(n, data):
    if not data or 'data' not in data:
        return None
    
    df = pd.DataFrame(data['data'])
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return dict(
        content=df.to_csv(index=False),
        filename=f"packet_analysis_{timestamp}.csv"
    )

# Reset dashboard
@app.callback(
    Output('data-store', 'data', allow_duplicate=True),
    Input('reset-btn', 'n_clicks'),
    prevent_initial_call=True
)
def reset_dashboard(n):
    processor.stop_live_capture()
    app_state.selected_app = 'All'
    app_state.selected_protocol = 'General'
    return {}

# Help button
@app.callback(
    Output('help-btn', 'n_clicks'),
    Input('help-btn', 'n_clicks'),
    prevent_initial_call=True
)
def show_help(n):
    print("\n" + "="*60)
    print("NETWORK PACKET ANALYZER - HELP")
    print("="*60)
    print("\n📖 Quick Guide:")
    print("  1. Select Mode: Previous (file) or Live (capture)")
    print("  2. Previous: Upload .pcap or .csv file")
    print("  3. Live: Click Start Capture (needs sudo)")
    print("  4. Filter by clicking apps or protocol buttons")
    print("  5. Export results with Export CSV button")
    print("\n🔧 Troubleshooting:")
    print("  • Permission denied: Run with sudo")
    print("  • No data: Check file format or network activity")
    print("  • High memory: Reduce capture duration")
    print("\n📊 Metrics:")
    print("  • Delay: Time between packets")
    print("  • Jitter: Variation in delay")
    print("  • Packet Loss: Percentage of lost packets")
    print("\n" + "="*60 + "\n")
    return None

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 NETWORK PACKET ANALYZER")
    print("="*60)
    print(f"\n📊 Dashboard: http://127.0.0.1:8050")
    print(f"🐍 Python: {os.sys.version.split()[0]}")
    print(f"💾 OS-Safe: Memory limited, CPU protected")
    
    # Check dependencies
    print("\n📦 Dependencies:")
    print(f"  • psutil: {'✓' if HAS_PSUTIL else '✗ (optional)'}")
    print(f"  • pyshark: {'✓' if HAS_PYSHARK else '✗ (PCAP limited)'}")
    print(f"  • scapy: {'✓' if HAS_SCAPY else '✗ (no live capture)'}")
    
    if not HAS_SCAPY and not HAS_PYSHARK:
        print("\n⚠️  WARNING: No capture libraries available!")
        print("   Install: pip install scapy pyshark")
    
    print("\n💡 Tips:")
    print("  • For live capture: sudo python3 network_analyzer.py")
    print("  • Test with sample data first")
    print("  • Press Ctrl+C to stop")
    
    print("\n" + "="*60)
    print("Starting server...\n")
    
    try:
        app.run_server(debug=False, host='127.0.0.1', port=8050)
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down gracefully...")
        processor.stop_live_capture()
        print("✓ Stopped capture")
        print("✓ Cleaned up resources")
        print("Goodbye!\n")