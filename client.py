import socket,threading,time

def client_task(name, message, delay, results, idx):
	start = time.perf_counter()
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
			sock.connect(("localhost", 1234))
			if delay and delay > 0:
				time.sleep(delay)
			sock.send(message.encode('utf-8'))
			data = sock.recv(1024)
	except Exception as e:
		data = f"ERROR: {e}".encode('utf-8')
		results[idx] = None
		print(f"{name} error: {e}")
		return
	end = time.perf_counter()
	elapsed = end - start
	print(f"{name} received: {data.decode('utf-8')}")
	results[idx] = elapsed

def main():
	results = [None, None]

	t1 = threading.Thread(target=client_task, args=("Client1", "Hello from Client1", 5, results, 0))
	t2 = threading.Thread(target=client_task, args=("Client2", "Hello from Client2", 1, results, 1))

	overall_start = time.perf_counter()
	t1.start()
	t2.start()
	t1.join()
	t2.join()
	overall_end = time.perf_counter()

	total = overall_end - overall_start

	print(f"Client1 time: {results[0]:.4f}s" if results[0] is not None else "Client1 time: error")
	print(f"Client2 time: {results[1]:.4f}s" if results[1] is not None else "Client2 time: error")
	print(f"Total wall-clock time for both: {total:.4f}s")

if __name__ == "__main__":
	main()