# Description: A simple server that listens on port 8888
# and sends "Hello, World!" to any client that connects to it.
# 测试进程隐藏的简易样品
import socket

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8888))
    server_socket.listen(5)
    print("Server listening on port 8888")
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        client_socket.send(b"Hello, World!")
        client_socket.close()

if __name__ == "__main__":
    start_server()
