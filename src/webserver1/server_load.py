import requests
import time
import yaml
import psutil
import threading

config = None

with open("web_server_config.yml", "r") as f:
    config = yaml.safe_load(f)

def get_cpu_usage():
    return psutil.cpu_percent()

while True:
  try:
    cpu_usage = get_cpu_usage()
    load_data = {"ip": config["name"], "load": cpu_usage}
    response = requests.post(f"http://{config['dns_server_ip']}:8080", data=load_data)
    if response.status_code == 200:
        print("Load data sent successfully")
    else:
        print(f"Failed to send load data. Status code: {response.status_code}")
    time.sleep(5)
  except KeyboardInterrupt:
    break
  except Exception:
    pass