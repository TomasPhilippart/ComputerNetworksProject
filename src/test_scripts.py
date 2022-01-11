import requests
import os
import socket

# EDIT
IP = socket.gethostbyname(socket.gethostname())
PORT = 58043
url = "http://tejo.tecnico.ulisboa.pt/index.html"

print(f"IP: {IP}, Port: {PORT}")

os.system(f"./DS -p {PORT} -v")

script_number = 1

r = requests.get(url, params={'DSIP': IP,
                              'DSPORT': PORT,
                              'SCRIPT': script_number
                            })
print(f"URL: {r.url}")
print(r.text)