import unittest
import unittest.mock
import time
import logging
import os
import threading

import zmq

import pylibcamera.callback


class TestEventWidgit(unittest.TestCase):
    def test_thread_subroutine(self):
        cm = pylibcamera.callback.CallbackManager()
        shutdown = threading.Event()
        bound = threading.Event()
        shutdown.set()
        cm._thread_run(shutdown, bound)
        assert bound.is_set()

    def test_start_stop(self):
        cm = pylibcamera.callback.CallbackManager()
        cm.start_callback_thread()
        cm.stop_callback_thread()

    def test_start_stop_full(self):
        call_many = unittest.mock.MagicMock()
        call_once = unittest.mock.MagicMock()

        cm = pylibcamera.callback.CallbackManager()
        cm.add_callback(call_many)
        cm.add_call_once(call_once)

        cm.start_callback_thread()

        try:
            payload = b'????'
            with zmq.Context() as ctx:
                with zmq.Socket(ctx, zmq.REQ) as skt:
                    for _ in range(3):
                        skt.connect("ipc://.frame_notif")
                        skt.send(payload)
                        assert skt.poll(timeout=1000) != 0
                        assert skt.recv() == b"OK"
        finally:
            cm.stop_callback_thread()

        call_many.assert_has_calls([unittest.mock.call(payload,), unittest.mock.call(payload,), unittest.mock.call(payload,)])
        call_once.assert_called_once_with(payload)