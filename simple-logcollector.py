#!/usr/bin/env python3
"""
Multi-Protocol Network Listener
Collects syslog, Windows events, and NetFlow data on different ports and writes them to separate log files.

# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/ssl/private/server.key \
  -out /etc/ssl/certs/server.crt \
  -days 365 -subj "/CN=logcollector"

# Set proper permissions
chmod 600 /etc/ssl/private/server.key
chmod 644 /etc/ssl/certs/server.crt

"""

import socket
import ssl
import threading
import logging
from datetime import datetime, date
import struct
import json
from pathlib import Path
import os
import shutil
import glob

class LogListener:
    def __init__(self, config, log_directory='logs', min_free_space_gb=10):
        """
        Initialize the listener with configuration.
        
        config format:
        {
            'syslog': {'port': 514, 'protocol': 'UDP', 'logfile': 'syslog.log'},
            'winevent': {'port': 515, 'protocol': 'TCP', 'logfile': 'winevent.log', 
                        'ssl': True, 'certfile': '/path/to/cert.pem', 'keyfile': '/path/to/key.pem'},
            'netflow': {'port': 2055, 'protocol': 'UDP', 'logfile': 'netflow.log'}
        }
        log_directory: base directory for log files (default: 'logs')
        min_free_space_gb: minimum free space in GB before cleanup (default: 10)
        """
        self.config = config
        self.log_directory = log_directory
        self.min_free_space_gb = min_free_space_gb
        self.running = False
        self.threads = []
        self.sockets = []
        self.file_handles = {}
        self.file_dates = {}
        self.file_locks = {}
        
        # NetFlow v9 template storage
        self.netflow_templates = {}
        self.template_lock = threading.Lock()
        
        # Create log directory if it doesn't exist
        Path(self.log_directory).mkdir(parents=True, exist_ok=True)
        
        # Setup logging for the listener itself
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _check_disk_space(self):
        """Check available disk space and return free space in GB."""
        stat = shutil.disk_usage(self.log_directory)
        free_gb = stat.free / (1024**3)
        return free_gb

    def _cleanup_old_logs(self):
        """Remove oldest log files until sufficient space is available."""
        try:
            free_space = self._check_disk_space()
            
            if free_space >= self.min_free_space_gb:
                return
            
            self.logger.warning(f"Low disk space: {free_space:.2f} GB free. Starting cleanup...")
            
            # Get all log files with timestamps
            log_files = []
            for pattern in ['*.log']:
                for filepath in glob.glob(os.path.join(self.log_directory, pattern)):
                    if os.path.isfile(filepath):
                        mtime = os.path.getmtime(filepath)
                        size = os.path.getsize(filepath)
                        log_files.append((filepath, mtime, size))
            
            # Sort by modification time (oldest first)
            log_files.sort(key=lambda x: x[1])
            
            # Delete oldest files until we have enough space
            for filepath, mtime, size in log_files:
                # Don't delete today's files
                file_date = datetime.fromtimestamp(mtime).date()
                if file_date == date.today():
                    continue
                
                try:
                    os.remove(filepath)
                    self.logger.info(f"Deleted old log file: {filepath}")
                    
                    # Check if we have enough space now
                    free_space = self._check_disk_space()
                    if free_space >= self.min_free_space_gb:
                        self.logger.info(f"Cleanup complete. Free space: {free_space:.2f} GB")
                        return
                        
                except Exception as e:
                    self.logger.error(f"Error deleting {filepath}: {e}")
            
            # Final check
            free_space = self._check_disk_space()
            if free_space < self.min_free_space_gb:
                self.logger.error(f"Cleanup complete but still low on space: {free_space:.2f} GB")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def _get_log_file(self, service, base_logfile):
        """Get the current log file handle with daily rotation."""
        today = date.today()
        
        # Initialize lock for this service if it doesn't exist
        if service not in self.file_locks:
            self.file_locks[service] = threading.Lock()
        
        with self.file_locks[service]:
            # Check if we need to rotate (new day or first time)
            if service not in self.file_dates or self.file_dates[service] != today:
                # Close old file if it exists
                if service in self.file_handles:
                    self.file_handles[service].close()
                
                # Check disk space and cleanup if needed
                self._cleanup_old_logs()
                
                base_logfile = os.path.basename(base_logfile)
                
                # Create new filename with date
                base_name = base_logfile.rsplit('.', 1)[0]
                extension = base_logfile.rsplit('.', 1)[1] if '.' in base_logfile else 'log'
                dated_filename = os.path.join(self.log_directory, f"{base_name}_{today.strftime('%Y%m%d')}.{extension}")
                
                # Open new file
                self.file_handles[service] = open(dated_filename, 'a', encoding='utf-8')
                self.file_dates[service] = today
                self.logger.info(f"Opened new log file for {service}: {dated_filename}")
            
            return self.file_handles[service]

    def _write_log(self, service, base_logfile, log_entry):
        """Write log entry with daily rotation support."""
        f = self._get_log_file(service, base_logfile)
        f.write(log_entry + '\n')
        f.flush()

    def start(self):
        """Start all listeners."""
        self.running = True
        
        for service, settings in self.config.items():
            port = settings['port']
            protocol = settings['protocol']
            logfile = settings['logfile']
            
            if protocol.upper() == 'UDP':
                thread = threading.Thread(
                    target=self._udp_listener,
                    args=(port, logfile, service),
                    daemon=True
                )
            else:  # TCP
                use_ssl = settings.get('ssl', False)
                certfile = settings.get('certfile')
                keyfile = settings.get('keyfile')
                
                thread = threading.Thread(
                    target=self._tcp_listener,
                    args=(port, logfile, service, use_ssl, certfile, keyfile),
                    daemon=True
                )
            
            thread.start()
            self.threads.append(thread)
            ssl_status = " (SSL enabled)" if settings.get('ssl') else ""
            self.logger.info(f"Started {service} listener on {protocol} port {port}{ssl_status}")
        
        self.logger.info("All listeners started. Press Ctrl+C to stop.")

    def _udp_listener(self, port, logfile, service):
        """Handle UDP connections (syslog, NetFlow)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.settimeout(1.0)
        self.sockets.append(sock)
        
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
                timestamp = datetime.now().isoformat()
                
                # Determine parsing based on service type
                if service == 'netflow':
                    log_entry = self._parse_netflow(data, addr, timestamp)
                else:  # syslog format (works for syslog, infoblox, and other syslog-like services)
                    log_entry = self._parse_syslog(data, addr, timestamp)
                
                self._write_log(service, logfile, log_entry)
                
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Error in {service} UDP listener: {e}")
        
        sock.close()

    def _tcp_listener(self, port, logfile, service, use_ssl=False, certfile=None, keyfile=None):
        """Handle TCP connections (Windows events) with optional SSL/TLS."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        sock.settimeout(1.0)
        self.sockets.append(sock)
        
        # Setup SSL context if enabled
        ssl_context = None
        if use_ssl:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            
            if certfile and keyfile:
                try:
                    ssl_context.load_cert_chain(certfile, keyfile)
                    self.logger.info(f"SSL enabled for {service} with cert: {certfile}")
                except Exception as e:
                    self.logger.error(f"Error loading SSL certificates for {service}: {e}")
                    return
            else:
                self.logger.error(f"SSL enabled for {service} but certfile/keyfile not provided")
                return
        
        while self.running:
            try:
                conn, addr = sock.accept()
                
                # Wrap socket with SSL if enabled
                if ssl_context:
                    try:
                        conn = ssl_context.wrap_socket(conn, server_side=True)
                    except Exception as e:
                        self.logger.error(f"SSL handshake failed for {service} from {addr}: {e}")
                        conn.close()
                        continue
                
                thread = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(conn, addr, logfile, service),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Error in {service} TCP listener: {e}")
        
        sock.close()

    def _handle_tcp_client(self, conn, addr, logfile, service):
        """Handle individual TCP client connection."""
        try:
            while self.running:
                data = conn.recv(4096)
                if not data:
                    break
                
                timestamp = datetime.now().isoformat()
                log_entry = self._parse_winevent(data, addr, timestamp)
                
                self._write_log(service, logfile, log_entry)
                
        except Exception as e:
            self.logger.error(f"Error handling {service} client {addr}: {e}")
        finally:
            conn.close()

    def _parse_syslog(self, data, addr, timestamp):
        """Parse syslog message."""
        try:
            message = data.decode('utf-8', errors='replace').strip()
            return f"[{timestamp}] [{addr[0]}:{addr[1]}] {message}"
        except Exception as e:
            return f"[{timestamp}] [{addr[0]}:{addr[1]}] ERROR: {e} | RAW: {data.hex()}"

    def _parse_winevent(self, data, addr, timestamp):
        """Parse Windows event log message."""
        try:
            # Assuming Windows events are sent as text or JSON
            message = data.decode('utf-8', errors='replace').strip()
            return f"[{timestamp}] [{addr[0]}:{addr[1]}] {message}"
        except Exception as e:
            return f"[{timestamp}] [{addr[0]}:{addr[1]}] ERROR: {e} | RAW: {data.hex()}"

    def _parse_netflow(self, data, addr, timestamp):
        """Parse NetFlow v9 packet with full template support."""
        try:
            if len(data) < 20:
                return f"[{timestamp}] [{addr[0]}:{addr[1]}] Invalid NetFlow packet (too short)"
            
            # NetFlow v9 header (20 bytes)
            version, count, sys_uptime, unix_secs, sequence, source_id = struct.unpack('!HHIIII', data[0:20])
            
            if version != 9:
                return f"[{timestamp}] [{addr[0]}:{addr[1]}] Unsupported NetFlow version: {version}"
            
            exporter_key = f"{addr[0]}:{source_id}"
            
            flow_info = {
                'timestamp': timestamp,
                'exporter': addr[0],
                'exporter_port': addr[1],
                'source_id': source_id,
                'sequence': sequence,
                'flows': []
            }
            
            # Parse FlowSets
            offset = 20
            while offset < len(data):
                if offset + 4 > len(data):
                    break
                    
                flowset_id, flowset_length = struct.unpack('!HH', data[offset:offset+4])
                
                if flowset_length < 4 or offset + flowset_length > len(data):
                    break
                
                # Template FlowSet (ID 0)
                if flowset_id == 0:
                    self._parse_netflow_template(data[offset+4:offset+flowset_length], exporter_key)
                
                # Data FlowSet (ID >= 256)
                elif flowset_id >= 256:
                    flows = self._parse_netflow_data(data[offset+4:offset+flowset_length], 
                                                     flowset_id, exporter_key)
                    flow_info['flows'].extend(flows)
                
                offset += flowset_length
            
            return json.dumps(flow_info)
            
        except Exception as e:
            return f"[{timestamp}] [{addr[0]}:{addr[1]}] ERROR parsing NetFlow: {e}"

    def _parse_netflow_template(self, data, exporter_key):
        """Parse NetFlow v9 template."""
        try:
            offset = 0
            with self.template_lock:
                while offset + 4 <= len(data):
                    template_id, field_count = struct.unpack('!HH', data[offset:offset+4])
                    offset += 4
                    
                    fields = []
                    for _ in range(field_count):
                        if offset + 4 > len(data):
                            break
                        field_type, field_length = struct.unpack('!HH', data[offset:offset+4])
                        fields.append({'type': field_type, 'length': field_length})
                        offset += 4
                    
                    # Store template only if new or changed
                    template_key = f"{exporter_key}:{template_id}"
                    if template_key not in self.netflow_templates or self.netflow_templates[template_key] != fields:
                        self.netflow_templates[template_key] = fields
                        self.logger.info(f"Stored NetFlow template {template_id} from {exporter_key} with {field_count} fields")
                    
        except Exception as e:
            self.logger.error(f"Error parsing NetFlow template: {e}")

    def _parse_netflow_data(self, data, template_id, exporter_key):
        """Parse NetFlow v9 data using stored template."""
        flows = []
        
        try:
            template_key = f"{exporter_key}:{template_id}"
            
            with self.template_lock:
                if template_key not in self.netflow_templates:
                    return [{'error': f'No template found for ID {template_id}'}]
                
                template = self.netflow_templates[template_key]
            
            # Calculate record length
            record_length = sum(field['length'] for field in template)
            
            offset = 0
            while offset + record_length <= len(data):
                flow_record = {}
                field_offset = offset
                
                for field in template:
                    field_type = field['type']
                    field_length = field['length']
                    field_data = data[field_offset:field_offset+field_length]
                    
                    # Parse common NetFlow v9 fields
                    value = self._parse_netflow_field(field_type, field_data)
                    if value is not None:
                        flow_record.update(value)
                    
                    field_offset += field_length
                
                if flow_record:
                    flows.append(flow_record)
                
                offset += record_length
                
        except Exception as e:
            self.logger.error(f"Error parsing NetFlow data: {e}")
            flows.append({'error': str(e)})
        
        return flows

    def _parse_netflow_field(self, field_type, field_data):
        """Parse individual NetFlow v9 field."""
        try:
            # Common NetFlow v9 field types
            field_map = {
                1: 'in_bytes',
                2: 'in_pkts',
                4: 'protocol',
                5: 'src_tos',
                6: 'tcp_flags',
                7: 'l4_src_port',
                8: 'ipv4_src_addr',
                9: 'src_mask',
                10: 'input_snmp',
                11: 'l4_dst_port',
                12: 'ipv4_dst_addr',
                13: 'dst_mask',
                14: 'output_snmp',
                15: 'ipv4_next_hop',
                16: 'src_as',
                17: 'dst_as',
                21: 'last_switched',
                22: 'first_switched',
                27: 'ipv6_src_addr',
                28: 'ipv6_dst_addr',
                60: 'ip_protocol_version',
            }
            
            field_name = field_map.get(field_type)
            if not field_name:
                return None
            
            # Parse based on field type
            if field_type == 8 or field_type == 12 or field_type == 15:  # IPv4 addresses
                if len(field_data) == 4:
                    ip = '.'.join(str(b) for b in field_data)
                    return {field_name: ip}
            
            elif field_type == 27 or field_type == 28:  # IPv6 addresses
                if len(field_data) == 16:
                    ip = ':'.join(f'{field_data[i]:02x}{field_data[i+1]:02x}' for i in range(0, 16, 2))
                    return {field_name: ip}
            
            elif field_type == 7 or field_type == 11:  # Ports
                if len(field_data) == 2:
                    port = struct.unpack('!H', field_data)[0]
                    return {field_name: port}
            
            elif field_type == 4:  # Protocol
                if len(field_data) == 1:
                    protocol = field_data[0]
                    protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                    return {
                        'protocol': protocol,
                        'protocol_name': protocol_names.get(protocol, f'PROTO_{protocol}')
                    }
            
            elif field_type in [1, 2]:  # Bytes/Packets (can be 4 or 8 bytes)
                if len(field_data) == 4:
                    value = struct.unpack('!I', field_data)[0]
                    return {field_name: value}
                elif len(field_data) == 8:
                    value = struct.unpack('!Q', field_data)[0]
                    return {field_name: value}
            
            elif len(field_data) == 1:  # 1-byte values
                return {field_name: field_data[0]}
            
            elif len(field_data) == 2:  # 2-byte values
                value = struct.unpack('!H', field_data)[0]
                return {field_name: value}
            
            elif len(field_data) == 4:  # 4-byte values
                value = struct.unpack('!I', field_data)[0]
                return {field_name: value}
            
        except Exception as e:
            self.logger.error(f"Error parsing field {field_type}: {e}")
        
        return None

    def stop(self):
        """Stop all listeners."""
        self.logger.info("Stopping all listeners...")
        self.running = False
        
        # Close all sockets
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=2)
        
        # Close all log files
        for service, fh in self.file_handles.items():
            try:
                fh.close()
                self.logger.info(f"Closed log file for {service}")
            except:
                pass
        
        self.logger.info("All listeners stopped.")


def main():
    # Configuration
    config = {
        'syslog': {
            'port': 514,
            'protocol': 'UDP',
            'logfile': 'syslog.log'
        },
        'checkpoint': {
            'port': 9001,
            'protocol': 'UDP',
            'logfile': 'checkpoint.log'
        },
        'trendmicro': {
            'port': 9002,
            'protocol': 'UDP',
            'logfile': 'trendmicro.log'
        },
        'infoblox': {
            'port': 9003,
            'protocol': 'UDP',
            'logfile': 'infoblox.log'
        },
        'f5': {
            'port': 9004,
            'protocol': 'UDP',
            'logfile': 'f5.log'
        },
        'winevent': {
            'port': 515,
            'protocol': 'TCP',
            'logfile': 'winevent.log',
            'ssl': True,
            'certfile': '/etc/ssl/certs/server.crt',
            'keyfile': '/etc/ssl/private/server.key'
        },
        'netflow': {
            'port': 2055,
            'protocol': 'UDP',
            'logfile': 'netflow.log'
        }
    }
    
    log_directory = '/data/logs/'
    min_free_space_gb = 10  # Minimum free space in GB before cleanup
    
    listener = LogListener(config, log_directory, min_free_space_gb)
    
    try:
        listener.start()
        
        # Keep main thread alive
        while True:
            threading.Event().wait(1)
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        listener.stop()


if __name__ == '__main__':
    main()
