import threading
import logging
import os

import zmq


class CallbackManager:
    """
    This class is a bridge between the libcamera callback structure
    and Python. It binds and listens to a zmq.PULL socket, and issues
    callbacks into Python with the messages received by the socket.
    """

    _url = "ipc://.frame_notif"
    def __init__(self):
        self._log = logging.getLogger(__name__)
        self._thread = None
        
        self._callbacks = []
        self._call_onces = []
        self._bound = threading.Event()
        self._shutdown = threading.Event()

        backend_v = ".".join(str(i) for i in zmq.backend.zmq_version_info())
        pyzmq_v = zmq.__version__
        self._log.info(f"PyZmq version: {pyzmq_v} Backend: {backend_v}") 
    
    def get_url(self):
        return self._url

    def _rm_socket(self):
        try:
            os.remove(self._url.split("//")[1])
            self._log.debug("Removed socket file")
        except FileNotFoundError:
            pass
    
    def _try_except_log(self, call, *args, **kwargs):
        try:
            call(*args, **kwargs)
            return True
        except Exception as e:
            self._log.exception("Callback triggered an exception", exc_info=e)
        return False

    def _run_callbacks(self, payload: bytes):
        n_called = 0
        while len(self._call_onces) > 0:
            n_called += self._try_except_log(self._call_onces.pop(), payload)

        for callback in self._callbacks:
            n_called += self._try_except_log(callback, payload)
            
        self._log.debug("Delivered %i callbacks", n_called)

    def _thread_run(self, shutdown: threading.Event, bound: threading.Event):
        self._log.debug("Thread started")
        self._rm_socket()
        with zmq.Context.instance() as ctx:
            with ctx.socket(zmq.REP).bind(self._url) as skt:
                bound.set()
                self._log.debug("Bound endopoint")
                while not shutdown.is_set():
                    if skt.poll(timeout=250) == 0:
                        self._log.debug("No messages...")
                        continue
                    payload = skt.recv()
                    self._log.debug("Received %i bytes", len(payload))
                    self._run_callbacks(payload)
                    skt.send(b"OK")
                    self._log.debug("Sent OK")
                skt.close(250)
                self._log.debug("Exiting Socket Context")
            self._rm_socket()
        self._log.debug("Exiting Thread")

    def add_callback(self, cb: callable) -> None:
        self._callbacks.append(cb)

    def add_call_once(self, cb: callable) -> None:
        self._call_onces.append(cb)

    def __enter__(self):
        self.start_callback_thread()
        return self
    
    def __exit__(self, *args):
        self.stop_callback_thread()

    def start_callback_thread(self):
        """Start the thread that watches for callbacks"""
        self._log.debug("Callback Manager Starting")
        assert self._thread is None
        self._shutdown.clear()
        self._bound.clear()
        self._thread = threading.Thread(
            target=self._thread_run,
            args=(self._shutdown, self._bound)
        )
        self._thread.daemon =True
        self._thread.start()
        assert self._bound.wait(timeout=1.0), "Thread did not set bind"
    
    def stop_callback_thread(self):
        """Stop the socket watcher. Raises AssertionError if the thread does not stop."""
        self._log.debug("Callback Manager Stopping")
        if self._thread is None:
            return
        assert self._thread.is_alive(), "Unexpected thread shutdown"
        self._shutdown.set()
        self._thread.join(1.0)
        assert not self._thread.is_alive(), "Thread did not terminate!"
        self._thread = None
