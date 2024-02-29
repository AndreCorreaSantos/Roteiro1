import socket
import sys
from cmd import Cmd
import concurrent.futures

class PortScanner(Cmd):
    prompt = 'scanner> '
    intro = 'Welcome to the simple TCP port scanner! Type help or ? to list commands.\n'

    def do_scan(self, args):
        "Scan a specific port or range of ports on a given IP: scan [ip] [start_port] [end_port]"
        args = args.split()
        if len(args) != 3:
            print("Usage: scan [ip] [start_port] [end_port]")
            return
        
        remote_server_ip, start_port, end_port = args[0], int(args[1]), int(args[2])
        if start_port > end_port:
            print("Start port must be less than or equal to end port")
            return
        if start_port < 0 or end_port > 65535:
            print("Port range must be between 0 and 65535")
            return
        self.tcp_scanner(range(start_port, end_port + 1), remote_server_ip)

    def tcp_scanner(self, port_range, remote_server_ip):

        max_threads = 100  # Limiting the number of threads to 10
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port, remote_server_ip): port for port in port_range}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"Error scanning port {port}: {e}")

    def scan_port(self, port, remote_server_ip):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((remote_server_ip, port))
            if result == 0:
                service = socket.getservbyport(port, 'tcp')
                print(f"Port {port}: Open, Service: {service}")
            sock.close()


    def do_exit(self, inp):
        "Exit the scanner"
        print("Exiting")
        return True



scanner = PortScanner()
scanner.cmdloop()