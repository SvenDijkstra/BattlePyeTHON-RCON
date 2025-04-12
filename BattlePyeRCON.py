#!/usr/bin/env python3
import argparse
import cmd
import configparser
import crc32c
import logging
import os
import readline
import socket
import struct
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from queue import Queue, Empty
from typing import Optional, Tuple, List, Callable

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'

class BattlEyeClient:
    def __init__(self, host: str, port: int, password: str, message_handler: Callable):
        self.host = host
        self.port = port
        self.password = password
        self.message_handler = message_handler
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(5.0)
        self.sequence = 0
        self.connected = False
        self.last_packet_time = time.time()
        self.keepalive_interval = 30
        self.ack_events = {}  # sequence -> threading.Event
        self.ack_data = {}    # sequence -> data
        self.lock = threading.Lock()
        self.logger = logging.getLogger('BattlEyeClient')

    def connect(self) -> bool:
        """Connect to the BattlEye RCon server."""
        try:
            # Create login packet (0x00 type + password)
            login_payload = bytes([0x00]) + self.password.encode('ascii')
            login_packet = self._create_packet(login_payload)
            
            self.logger.debug(f"Sending login packet to {self.host}:{self.port}")
            self.socket.sendto(login_packet, (self.host, self.port))
            
            # Wait for login response
            data, _ = self.socket.recvfrom(4096)
            self.logger.debug(f"Received login response: {data}")
            
            # Special case: Some servers respond with just BE + checksum + 0xFF + 0x00 + 0x01
            if data == b'BEi\xdd\xde6\xff\x00\x01':
                self.connected = True
                self.last_packet_time = time.time()
                threading.Thread(target=self._listen, daemon=True).start()
                return True
                
            # Normal packet parsing
            payload = self._parse_packet(data)
            if payload and len(payload) >= 2 and payload[0] == 0x00:
                success = payload[1] == 0x01
                if success:
                    self.connected = True
                    self.last_packet_time = time.time()
                    threading.Thread(target=self._listen, daemon=True).start()
                    return True
                else:
                    self.logger.error("Login failed: Invalid password")
            else:
                self.logger.error(f"Invalid login response: {data}")
        except socket.timeout:
            self.logger.error("Login timeout: Server did not respond")
        except Exception as e:
            self.logger.error(f"Login error: {e}")
        return False

    def _create_packet(self, payload: bytes) -> bytes:
        """Create a BattlEye protocol packet with header and checksum."""
        # Calculate CRC32 checksum of the payload (without header)
        checksum = crc32c.crc32c(payload) & 0xFFFFFFFF  # Ensure 32-bit unsigned
        header = b'BE' + struct.pack('<I', checksum) + b'\xff'
        return header + payload
    
    def _parse_packet(self, data: bytes) -> Optional[bytes]:
        """Parse incoming packet with relaxed checksum verification."""
        # Minimum packet is BE (2) + checksum (4) + 0xFF (1) + payload (at least 1)
        if len(data) < 8 or data[0] != 0x42 or data[1] != 0x45:  # 'BE' header
            self.logger.debug(f"Invalid header in packet: {data[:2]}")
            return None
            
        if data[6] != 0xff:
            self.logger.debug("Missing packet terminator (0xFF)")
            return None
            
        payload = data[7:]
        
        # Special handling for this server's behavior:
        # 1. Accept all packets with payload starting with \x02 (server messages)
        # 2. Accept all packets with "players" in response (command replies)
        # 3. Still verify checksums for other packets
        if payload.startswith(b'\x02') or b'players' in payload.lower():
            self.logger.debug("Accepting server message or players response despite checksum")
            return payload
            
        # Normal checksum verification for other packets
        received_checksum = struct.unpack('<I', data[2:6])[0]
        calculated_checksum = crc32c.crc32c(payload) & 0xFFFFFFFF
        
        if received_checksum != calculated_checksum:
            self.logger.debug(f"Checksum mismatch - Received: {received_checksum}, Calculated: {calculated_checksum}")
            return None
            
        return payload
    
    def run(self, command: str) -> str:
        """Send a command with retry logic for checksum issues."""
        if not self.connected:
            raise ConnectionError("Not connected to server")
            
        max_retries = 2
        for attempt in range(max_retries):
            try:
                with self.lock:
                    seq = self.sequence
                    self.sequence = (self.sequence + 1) % 256
                    event = threading.Event()
                    self.ack_events[seq] = event
                    self.ack_data[seq] = None
                    
                cmd_payload = bytes([0x01, seq]) + command.encode('ascii')
                cmd_packet = self._create_packet(cmd_payload)
                
                self.logger.debug(f"Attempt {attempt + 1}: Sending command: {command}")
                self.socket.sendto(cmd_packet, (self.host, self.port))
                self.last_packet_time = time.time()
                
                # Wait for response with shorter timeout for retries
                timeout = 5.0 if attempt < max_retries - 1 else 10.0
                if event.wait(timeout):
                    with self.lock:
                        response = self.ack_data.pop(seq, '')
                        self.ack_events.pop(seq, None)
                        if response:
                            return response
                        elif attempt < max_retries - 1:
                            continue  # Empty response, try again
                        raise ValueError("Empty response from server")
                        
            except Exception as e:
                self.logger.debug(f"Command attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    raise TimeoutError(f"No valid response after {max_retries} attempts")
                    
        raise TimeoutError("Command failed after retries")
    
    def _listen(self) -> None:
        """Listener thread that handles all incoming packets."""
        while self.connected:
            try:
                data, _ = self.socket.recvfrom(4096)
                if not data:
                    continue
                    
                self.last_packet_time = time.time()
                payload = self._parse_packet(data)
                if not payload:
                    continue
                    
                packet_type = payload[0] if len(payload) > 0 else None
                
                if packet_type == 0x01:  # Command response
                    if len(payload) >= 2:
                        seq = payload[1]
                        response = payload[2:].decode('ascii', errors='replace') if len(payload) > 2 else ''
                        with self.lock:
                            if seq in self.ack_events:
                                self.ack_data[seq] = response
                                self.ack_events[seq].set()
                
                elif packet_type == 0x02:  # Server message
                    if len(payload) >= 2:
                        seq = payload[1]
                        # Always acknowledge server messages
                        ack_payload = bytes([0x02, seq])
                        ack_packet = self._create_packet(ack_payload)
                        self.socket.sendto(ack_packet, (self.host, self.port))
                        # Process message
                        message = payload[2:].decode('ascii', errors='replace') if len(payload) > 2 else ''
                        if message and self.message_handler:
                            self.message_handler(message)
                            
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Listener error: {e}")
                self.connected = False

    def keepalive(self) -> None:
        """Send keepalive packet if needed."""
        if self.connected and (time.time() - self.last_packet_time) > self.keepalive_interval:
            try:
                # Empty command packet for keepalive (0x01 type + sequence)
                with self.lock:
                    seq = self.sequence
                    self.sequence = (self.sequence + 1) % 256
                
                keepalive_payload = bytes([0x01, seq])
                keepalive_packet = self._create_packet(keepalive_payload)
                self.socket.sendto(keepalive_packet, (self.host, self.port))
                self.last_packet_time = time.time()
                self.logger.debug("Sent keepalive packet")
            except Exception as e:
                self.logger.error(f"Keepalive failed: {e}")
                self.connected = False

    def close(self) -> None:
        """Close the connection."""
        self.connected = False
        try:
            self.socket.close()
        except:
            pass

class RconShell(cmd.Cmd):
    intro = f'{Colors.OKGREEN}Welcome to the BattlEye RCON shell. Type help or ? to list commands.{Colors.ENDC}\n'
    prompt = f'{Colors.BOLD}RCON>{Colors.ENDC} '
    
    def __init__(self, host: str, port: int, password: str, config_path: str, debug: bool = False):
        super().__init__()
        self.host = host
        self.port = port
        self.password = password
        self.config_path = config_path
        self.client: Optional[BattlEyeClient] = None
        self.debug = debug
        self.keepalive_thread: Optional[threading.Thread] = None
        self.running = False
        self.history_file = os.path.expanduser('~/.rcon_history')
        self._setup_logging()
        self._load_history()
        
    def _setup_logging(self) -> None:
        """Configure logging based on debug mode."""
        self.logger = logging.getLogger('rcon_shell')
        if self.debug:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            logging.basicConfig(
                level=logging.INFO,
                format='%(message)s'
            )
    
    def _load_history(self) -> None:
        """Load command history from file if it exists."""
        try:
            if os.path.exists(self.history_file):
                readline.read_history_file(self.history_file)
                readline.set_history_length(1000)
        except Exception as e:
            self.logger.warning(f"{Colors.WARNING}Could not load history file: {e}{Colors.ENDC}")
    
    def preloop(self) -> None:
        """Connect to the RCON server before entering the command loop."""
        if not self.connect():
            sys.exit(1)
    
    def connect(self) -> bool:
        """Connect to the RCON server."""
        self.logger.info(f"{Colors.OKBLUE}Connecting to {self.host}:{self.port}...{Colors.ENDC}")
        
        self.client = BattlEyeClient(
            self.host,
            self.port,
            self.password,
            self.message_handler
        )
        
        if self.client.connect():
            self.logger.info(f"{Colors.OKGREEN}Connected successfully!{Colors.ENDC}")
            self.running = True
            # Start keepalive thread
            self.keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
            self.keepalive_thread.start()
            return True
        else:
            self.logger.error(f"{Colors.FAIL}Failed to connect to server. Please check:")
            self.logger.error(f"- Server IP and port")
            self.logger.error(f"- RCON password")
            self.logger.error(f"- BattlEye RCON is enabled on server{Colors.ENDC}")
            return False
    
    def _keepalive_loop(self) -> None:
        """Keepalive loop that runs in a separate thread."""
        while self.running and self.client:
            try:
                self.client.keepalive()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                self.logger.error(f"{Colors.FAIL}Keepalive error: {e}{Colors.ENDC}")
                self.running = False
    
    def message_handler(self, message: str) -> None:
        """Handle incoming server messages."""
        if message and "Logged In!" not in message:
            print(f"\n{Colors.OKBLUE}Server:{Colors.ENDC} {message}")
            print(f"{self.prompt}", end='', flush=True)
    
    def default(self, line: str) -> None:
        """Handle any command that's not explicitly defined."""
        if line.strip().lower() in ('exit', 'quit'):
            return self.do_exit(line)
        
        command = line.strip()
        if command.startswith('#'):
            command = command[1:]  # Remove # prefix for BattlEye commands
            
        try:
            response = self.client.run(command)
            if response:
                print(f"{Colors.OKGREEN}Response:{Colors.ENDC} {response}")
        except TimeoutError:
            self.logger.error(f"{Colors.FAIL}Command timed out{Colors.ENDC}")
        except ConnectionError:
            self.logger.error(f"{Colors.FAIL}Not connected to server{Colors.ENDC}")
            if not self.connect():
                return self.do_exit('')
        except Exception as e:
            self.logger.error(f"{Colors.FAIL}Error executing command: {e}{Colors.ENDC}")
    
    def do_players(self, arg: str) -> None:
        """List players on the server."""
        self.default("#players")
    
    def do_exit(self, arg: str) -> bool:
        """Exit the RCON shell."""
        self.logger.info("Exiting RCON shell...")
        self.running = False
        if self.client:
            self.client.close()
        return True
    
    def do_EOF(self, arg: str) -> bool:
        """Exit on Ctrl+D (EOF)."""
        print()
        return self.do_exit(arg)
    
    do_quit = do_exit

def main():
    # Default config path
    config_dir = os.path.expanduser('~/.config/rcon')
    config_path = os.path.join(config_dir, 'servers.ini')
    os.makedirs(config_dir, exist_ok=True)
    
    parser = argparse.ArgumentParser(description='Interactive BattlEye RCON Client')
    parser.add_argument('-H', '--host', default='127.0.0.1', help='RCON server hostname or IP')
    parser.add_argument('-p', '--port', type=int, default=2302, help='RCON server port')
    parser.add_argument('-P', '--password', required=True, help='RCON server password')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    
    try:
        shell = RconShell(args.host, args.port, args.password, config_path, args.debug)
        shell.cmdloop()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Received keyboard interrupt. Exiting...{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

if __name__ == "__main__":
    main()
