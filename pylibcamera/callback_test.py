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
        mm = unittest.mock.MagicMock()

        cm = pylibcamera.callback.CallbackManager()
        cm.start_callback_thread()

        try:
            cm.add_callback(mm)

            payload = b'????'
            with zmq.Context() as ctx:
                with zmq.Socket(ctx, zmq.PUSH) as skt:
                    skt.connect("ipc://.frame_notif")
                    skt.send(payload)

            time.sleep(0.1)
            mm.assert_called_with(payload)
        finally:
            cm.stop_callback_thread()

