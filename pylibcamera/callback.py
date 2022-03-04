import zmq
import threading


class CallbackManager:
    def __init__(self):
        self._thread = None
        
        self.callbacks = []
        self.bound = threading.Event()
        self.shutdown = threading.Event()

    def _thread_run(self):
        with zmq.Context() as ctx:
            with zmq.Socket(ctx, zmq.PULL, kind="bind", addr="ipc://.frame_notif") as skt:
                self.bound.set()
                while not self.shutdown.is_set():
                    if skt.poll(100) == 0:
                        continue
                    payload = skt.recv()
                    for callback in self.callbacks:
                        callback(payload)

    def add_callback(self, cb: callable):
        self.callbacks.append(cb)

    def start_callback_thread(self):
        assert self._thread is None
        self.shutdown.clear()
        self.bound.clear()
        self._thread = threading.Thread(target=self._thread_run)
        self._thread.start()
        self.bound.wait(timeout=1.0) # seconds
    
    def stop_callback_thread(self):
        if self._thread is None:
            return
        assert self._thread.is_alive()
        self.shutdown.set()
        self._thread.join()
        self._thread = None
