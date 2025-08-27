import socket
import threading

USERS = {"admin": "1234"}  # login

def authenticate(conn):
    conn.sendall(b"Login: ")
    login = conn.recv(1024).decode().strip()
    conn.sendall(b"Senha: ")
    senha = conn.recv(1024).decode().strip()
    if USERS.get(login) == senha:
        conn.sendall(b"Autenticado com sucesso.\n")
        return True
    else:
        conn.sendall(b"Falha na autenticacao. Conexao encerrada.\n")
        return False

def ipv4_subnet_calc(network, mask, qtd):
    try:
        base = list(map(int, network.split('.')))
        if len(base) != 4 or not all(0 <= octet <= 255 for octet in base):
            return "Erro: Endereco IPv4 de rede invalido."
    except ValueError:
        return "Erro: Formato de endereco IPv4 invalido."
    
    subnet_bits_needed = (qtd - 1).bit_length() if qtd > 1 else 0
    new_mask = mask + subnet_bits_needed
    
    if new_mask > 30: 
        return f"Erro: Numero de sub-redes muito grande para a mascara / {mask} fornecida. A nova mascara excederia /30."

    hosts_per_subnet = 2 ** (32 - new_mask)

    subnets = []
    for i in range(qtd):
        subnet_ip_int = (base[0]<<24) + (base[1]<<16) + (base[2]<<8) + base[3] + i * hosts_per_subnet
        
        subnet_octets = [
            (subnet_ip_int >> 24) & 0xFF,
            (subnet_ip_int >> 16) & 0xFF,
            (subnet_ip_int >> 8) & 0xFF,
            subnet_ip_int & 0xFF
        ]
        
        if hosts_per_subnet < 4: 
            start_ip_str = "N/A"
            end_ip_str = "N/A"
        else:
            start_useful_ip_int = subnet_ip_int + 1
            end_useful_ip_int = subnet_ip_int + hosts_per_subnet - 2 
            
            start_ip_str = ".".join(str((start_useful_ip_int >> (8 * j)) & 0xFF) for j in reversed(range(4)))
            end_ip_str = ".".join(str((end_useful_ip_int >> (8 * j)) & 0xFF) for j in reversed(range(4)))
        
        subnets.append(f"{'.'.join(map(str, subnet_octets))}/{new_mask} {start_ip_str} {end_ip_str}")
    return "\n".join(subnets)

def ipv6_subnet_calc(prefix, mask, qtd):
    if ':' not in prefix:
        return "Erro: Endereco IPv6 de rede invalido. Formato incorreto."

    try:
        if '::' in prefix:
            parts = prefix.split('::')
            left = [p.zfill(4) for p in parts[0].split(':') if p]
            right = [p.zfill(4) for p in parts[1].split(':') if p]
            
            missing_parts = 8 - (len(left) + len(right))
            full_hex_str = "".join(left) + "0000" * missing_parts + "".join(right)
        else:
            full_hex_str = "".join([p.zfill(4) for p in prefix.split(':')])
            if len(prefix.split(':')) < 8:
                full_hex_str = full_hex_str.ljust(32, '0')

        if len(full_hex_str) != 32: 
            return "Erro: Endereco IPv6 de rede invalido. Comprimento incorreto."

        base_int = int(full_hex_str, 16)
    except Exception:
        return "Erro: Endereco IPv6 de rede invalido. Verifique o formato."

    subnet_bits_needed = (qtd - 1).bit_length() if qtd > 1 else 0
    new_mask = mask + subnet_bits_needed
    
    if new_mask > 128:
        return f"Erro: Numero de sub-redes muito grande para a mascara / {mask} fornecida. A nova mascara excederia /128."

    step = 2 ** (128 - new_mask)

    def int_to_ipv6(val):
        hex_val = f'{val:032x}' 
        
        parts = [hex_val[i:i+4] for i in range(0, 32, 4)]
        
        best_double_colon_start = -1
        max_zeros_length = 0
        current_zeros_length = 0
        current_zeros_start = -1

        for i, part in enumerate(parts):
            if part == '0000':
                if current_zeros_length == 0:
                    current_zeros_start = i
                current_zeros_length += 1
            else:
                if current_zeros_length > max_zeros_length and current_zeros_length > 1: 
                    max_zeros_length = current_zeros_length
                    best_double_colon_start = current_zeros_start
                current_zeros_length = 0
        
        if current_zeros_length > max_zeros_length and current_zeros_length > 1:
            max_zeros_length = current_zeros_length
            best_double_colon_start = current_zeros_start
        
        if best_double_colon_start != -1:
            new_parts = parts[:best_double_colon_start] + [''] + parts[best_double_colon_start + max_zeros_length:]
            return ':'.join(new_parts)
        
        return ':'.join(p.lstrip('0') or '0' for p in parts)

    results = []
    for i in range(qtd):
        subnet_start_int = base_int + i * step
        subnet_end_int = subnet_start_int + step - 1
        
        results.append(
            f"{int_to_ipv6(subnet_start_int)}/{new_mask} {int_to_ipv6(subnet_start_int)} - {int_to_ipv6(subnet_end_int)}"
        )
    return "\n".join(results)

def handle_client(conn):
    with conn:
        addr = conn.getpeername()
        print(f"[+] Conexao recebida de {addr}")

        if not authenticate(conn):
            print(f"[-] Falha na autenticacao do cliente {addr}. Conexao encerrada.")
            conn.close()
            return

        print(f"[+] Cliente {addr} autenticado com sucesso.")

        while True:
            try:
                conn.sendall(b"Escolha IP (4 ou 6, ou 'sair' para desconectar): ")
                ipver = conn.recv(1024).decode().strip().lower()
                if not ipver: 
                    print(f"[-] Cliente {addr} desconectou (input vazio).")
                    break
                if ipver == 'sair':
                    conn.sendall(b"Desconectando...\n")
                    print(f"[-] Cliente {addr} solicitou desconexao.")
                    break

                if ipver not in ["4", "6"]:
                    conn.sendall(b"Versao invalida. Por favor, escolha '4', '6' ou 'sair'.\n")
                    continue 

                conn.sendall(b"Endereco de rede: ")
                endereco = conn.recv(1024).decode().strip()
                if not endereco: break 

                conn.sendall(b"Mascara (sem /): ")
                mascara_str = conn.recv(1024).decode().strip()
                if not mascara_str: break 

                try:
                    mascara = int(mascara_str) 
                except ValueError:
                    conn.sendall(b"Erro: Mascara invalida. Deve ser um numero.\n")
                    continue
                

                if ipver == "4":
                    if not (16 <= mascara <= 29): 
                        conn.sendall(b"Erro: Mascara IPv4 invalida. Deve ser entre /16 e /29.\n")
                        continue
                elif ipver == "6":
                    if not (48 <= mascara <= 62): 
                        conn.sendall(b"Erro: Mascara IPv6 invalida. Deve ser entre /48 e /62.\n")
                        continue


                conn.sendall(b"Numero de sub-redes: ")
                qtd_str = conn.recv(1024).decode().strip()
                if not qtd_str: break 

                try:
                    qtd = int(qtd_str)
                    if qtd <= 0:
                        conn.sendall(b"Erro: Numero de sub-redes deve ser maior que zero.\n")
                        continue
                except ValueError:
                    conn.sendall(b"Erro: Numero de sub-redes invalido. Deve ser um numero.\n")
                    continue

                print(f"[>] Cliente {addr} requisitou calculo: IP{ipver}, rede {endereco}/{mascara}, {qtd} sub-redes")

                output = ""
                if ipver == "4":
                    output = ipv4_subnet_calc(endereco, mascara, qtd)
                elif ipver == "6":
                    output = ipv6_subnet_calc(endereco, mascara, qtd)
                
                if output.startswith("Erro:"):
                    conn.sendall(output.encode() + b"\n")
                    print(f"[!] Cliente {addr} recebeu erro: {output}")
                else:
                    print(f"[=] Enviando resultado ao cliente {addr}...\n{output}\n")
                    conn.sendall(output.encode() + b"\n")
                
                print(f"[✓] Finalizado para cliente {addr}\n")

            except ConnectionResetError:
                print(f"[-] Cliente {addr} desconectou abruptamente.")
                break 
            except Exception as e:
                print(f"[!] Erro inesperado ao lidar com cliente {addr}: {e}")
                conn.sendall(f"Erro interno do servidor: {e}\n".encode())
                break 
        
        conn.close()
        print(f"[*] Conexao com {addr} encerrada.")

def main():
    HOST = '127.0.0.1'
    PORT = 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Servidor ouvindo em {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn,)).start()

if __name__ == "__main__":
    main()