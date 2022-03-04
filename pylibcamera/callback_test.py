import unittest
import unittest.mock
import time
import os

import zmq

import pylibcamera.callback



class TestEventWidgit(unittest.TestCase):
    def test_start_stop(self):
        cm = pylibcamera.callback.CallbackManager()
        cm.start_callback_thread()
        assert os.path.exists(".frame_notif")
        time.sleep(0.1)
        cm.stop_callback_thread()

    def test_start_stop(self):
        mm = unittest.mock.MagicMock()

        cm = pylibcamera.callback.CallbackManager()
        cm.start_callback_thread()

        cm.add_callback(mm)

        payload = b'????'
        with zmq.Context() as ctx:
            with zmq.Socket(ctx, zmq.PUSH) as skt:
                skt.connect("ipc://.frame_notif")
                skt.send(payload)

        time.sleep(0.1)
        mm.assert_called_with(payload)
        cm.stop_callback_thread()

