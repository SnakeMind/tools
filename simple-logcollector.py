#!/usr/bin/env python3
"""
Multi-Protocol Network Listener
Collects syslog, Windows events, and NetFlow data on different ports
and writes them to separate log files.
"""

import socket
import threading
import logging
from datetime import datetime, date
import struct
import json
from pathlib import Path
import os

class LogListener:
    def __init__(self, config, log_directory='logs'):
        """
        Initialize the listener with configuration.
        
        config format:
        {
            'syslog': {'port': 514, 'protocol': 'UDP', 'logfile': 'syslog.log'},
            'winevent': {'port': 515, 'protocol': 'TCP', 'logfile': 'winevent.log'},
            'netflow': {'port': 2055, 'protocol': 'UDP', 'logfile': 'netflow.log'}
        }
        log_directory: base directory for log files (default: 'logs')
        """
        self.config = config
        self.log_directory = log_directory
        self.running = False
        self.threads = []
        self.sockets = []
        self.file_handles = {}
        self.file_dates = {}
        self.file_locks = {}
        
        # Create log directory if it doesn't exist
        Path(self.log_directory).mkdir(parents=True, exist_ok=True)
        
        # Setup logging for the listener itself
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

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
                
                # Remove any path components from base_logfile (just get the filename)
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
            logfile = f"logs/{settings['logfile']}"
            
            if protocol.upper() == 'UDP':
                thread = threading.Thread(
                    target=self._udp_listener,
                    args=(port, logfile, service),
                    daemon=True
                )
            else:  # TCP
                thread = threading.Thread(
                    target=self._tcp_listener,
                    args=(port, logfile, service),
                    daemon=True
                )
            
            thread.start()
            self.threads.append(thread)
            self.logger.info(f"Started {service} listener on {protocol} port {port}")
        
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

    def _tcp_listener(self, port, logfile, service):
        """Handle TCP connections (Windows events)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        sock.settimeout(1.0)
        self.sockets.append(sock)
        
        while self.running:
            try:
                conn, addr = sock.accept()
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
        """Parse NetFlow v5 packet (basic parsing)."""
        try:
            if len(data) < 24:
                return f"[{timestamp}] [{addr[0]}:{addr[1]}] Invalid NetFlow packet (too short)"
            
            # NetFlow v5 header
            version, count = struct.unpack('!HH', data[0:4])
            
            flow_info = {
                'timestamp': timestamp,
                'source': f"{addr[0]}:{addr[1]}",
                'version': version,
                'flow_count': count
            }
            
            return json.dumps(flow_info)
        except Exception as e:
            return f"[{timestamp}] [{addr[0]}:{addr[1]}] ERROR: {e} | RAW: {data[:50].hex()}"

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
        'infoblox': {
            'port': 9003,
            'protocol': 'UDP',
            'logfile': 'infoblox.log'
        },
        'winevent': {
            'port': 515,
            'protocol': 'TCP',
            'logfile': 'winevent.log'
        },
        'netflow': {
            'port': 2055,
            'protocol': 'UDP',
            'logfile': 'netflow.log'
        }
    }
    
    # Set your log directory here
    log_directory = '/data/logs'
    
    listener = LogListener(config, log_directory)
    
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
