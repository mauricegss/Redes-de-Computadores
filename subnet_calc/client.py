import socket

def main():
    HOST = '127.0.0.1'
    PORT = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            print(f"Conectado ao servidor em {HOST}:{PORT}")
        except ConnectionRefusedError:
            print(f"Erro: Nao foi possivel conectar ao servidor em {HOST}:{PORT}. Verifique se o servidor esta rodando.")
            return 

        while True:
            try:
                data = s.recv(1024).decode()
            except ConnectionResetError:
                print("Servidor desconectou abruptamente.")
                break
            except Exception as e:
                print(f"Erro ao receber dados do servidor: {e}")
                break

            if not data:
                print("Servidor desconectou normalmente.")
                break
            print(data, end="")

            if "Falha na autenticacao" in data or "Conexao encerrada" in data or "Desconectando" in data:
                print("Sessao encerrada pelo servidor.")
                break 
            
            if data.strip().endswith(":") or "Escolha IP" in data or "Endereco de rede" in data or "Mascara" in data or "Numero de sub-redes" in data:
                
                inp = ""
                if "Escolha IP" in data:
                    while True:
                        inp = input()
                        if inp.lower() in ['4', '6', 'sair']:
                            break
                        print("Escolha invalida. Digite '4' para IPv4, '6' para IPv6, ou 'sair' para desconectar.")
                elif "Mascara (sem /)" in data:
                    while True:
                        inp = input()
                        try:
                            mask = int(inp)
                            if 0 <= mask <= 128: 
                                break
                            print("Mascara invalida. Digite um numero entre 0 e 128.")
                        except ValueError:
                            print("Entrada invalida. Digite um numero para a mascara.")
                elif "Numero de sub-redes" in data:
                    while True:
                        inp = input()
                        try:
                            qtd = int(inp)
                            if qtd > 0:
                                break
                            print("Numero de sub-redes deve ser maior que zero.")
                        except ValueError:
                            print("Entrada invalida. Digite um numero para a quantidade de sub-redes.")
                else: 
                    inp = input()
                
                s.sendall(inp.encode())

            if "Erro:" in data:
                continue

        print("Conexao com o servidor encerrada.")

if __name__ == "__main__":
    main()