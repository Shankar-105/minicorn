# SEQUENTIAL EXECUTION OF REQUESTS (Synchronous Code)
# which means suppose there are two clients c1,c2
# to process c1 request it takes 10 seconds and
# to process c2 request it takes 1 second
# if c1 and c2 connects to the server almost at the same time that
# and c1 is connected just a milli second faster than c2 then
# c2 must wait all the 10 seconds for the server to process his request
# this the probelm with sync code it freezes at that single I/O bound request until its done

# import socket

# sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# sock.bind(("localhost",1234))
# sock.listen(5)
# try:
#     while(True):
#         client_sock,client_addr=sock.accept()
#         try:
#             print(f"Connection from {client_addr}")
#             msg = client_sock.recv(1024)
#             if not msg:
#                 break # No data, close connection
#             print(f"Received: {msg.decode('utf-8')}")
#             client_sock.send(b"Hello from Server")
#         finally:
#             # Gracefully close client connection
#             client_sock.close()
#             print("Client connection closed.")
# except Exception as e:
#     print(f"Server Shutting Down Due to an Exception {e}")
# finally :
#     sock.close()
#     print("Main socket closed.")


# CONCURRENT EXECUTION OF REQUESTS USING THREADS
# the same analogy as above but here we use threads that is
# upon every connetion we spwan a thread to that connection
# which means c2 don't need to wait all the 10 secs until c1 is done
# but rather his thread will be executed concurrently this is called CONCURRENCY

# import socket
# import threading

# def handle_client(client_sock, client_addr):
#     try:
#         data = client_sock.recv(1024)  # Blocks this thread only
#         print(f"From {client_addr}: {data.decode('utf-8')}")
#         client_sock.send(b"Hello from Server!")
#     except Exception as e:
#         print(f"Error with {client_addr}: {e}")
#     finally:
#         client_sock.close()

# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# sock.bind(("localhost", 1234))
# sock.listen(5)

# while True:
#     try:
#         client_sock, client_addr = sock.accept()
#         print(f"Connected: {client_addr}")
#         # Spawn thread: runs concurrently
#         threading.Thread(target=handle_client, args=(client_sock, client_addr)).start()
#     except Exception as e:
#         print(f"Accept error: {e}")


# CONCURRENT EXECUTION OF REQUESTS USING COROUTINES
# This section shows how to write the same server using asyncio and tasks
# instead of threads tasks are nothing but schduled coroutines which are 
# very lighter compared to threads 

import asyncio

# Explanation of core asyncio pieces used below:
# - `asyncio.run(coro())`: entry point to run the top-level coroutine; it
#    creates an event loop, runs the coroutine, and closes the loop when done.
# - `asyncio.start_server(callback, host, port)`: creates a TCP server that
#    calls `callback(reader, writer)` for each incoming connection. Each
#    callback runs as a Task concurrently (no OS threads needed).
#    read from and write to the socket (replacing `recv`/`send`).
# - `await reader.read(n)`: asynchronously read up to `n` bytes; suspends the
#    task but not the whole program while waiting for data.
# - `writer.write(data)`: queue bytes to send; must call `await writer.drain()`
#    to wait until the buffer is flushed.
# - `writer.close()` and `await writer.wait_closed()`: gracefully close the
#    connection from the server side.
# - `asyncio.create_task(coro())`: schedule a coroutine as a Task running
#    concurrently on the event loop (useful for background work).


import asyncio

async def handle_client(reader, writer):
    try:
        data = await reader.read(1024)  # Await: yields if not ready
        print(f"Received: {data.decode('utf-8')}")
        writer.write(b"Hello back!")
        await writer.drain()  # Await send
    except Exception as e:
        print(f"Error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle_client,'localhost',1234)
    async with server:
        await server.serve_forever()

asyncio.run(main())