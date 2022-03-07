import unittest

import pytest

import pylibcamera.wrapper

# These tests are designed to work against a virtual media device
# To build this interface
# sudo modprobe vimc
# media-ctl -d platform:vimc -V '"Sensor B":0[fmt:SBGGR8_1X8/640x480]'

class TestLibCameraWrapper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._cam_manager = pylibcamera.wrapper.PyCameraManager()

    @classmethod
    def teatDownClass(cls):
        cls._cam_manager.close()

    def test_camera_manager_wrapper(self):
        assert self._cam_manager.get_n_cameras() >= 0

    def test_get_names(self):
        names = self._cam_manager.get_camera_names()
        assert len(names) == self._cam_manager.get_n_cameras()

    def test_get_version(self):
        assert "0.0.0" in self._cam_manager.version()

    def _skip_if_no_camera(self):
        if self._cam_manager.get_n_cameras() == 0:
            self.skipTest("No cameras available on this system")

    def test_get_camera(self):
        self._skip_if_no_camera()

        c = self._cam_manager.get_camera(0)

        # Test close is idempotent
        for _ in range(3):
            c.close()

    def test_get_controls(self):
        self._skip_if_no_camera()

        camera = self._cam_manager.get_camera_matching("vimc")

        try:        
            camera.configure()  
            controls = camera.get_controls()

            assert isinstance(controls, dict)
            assert len(controls) >= 3
        finally:
            camera.close()

    def test_everything(self):
        self._skip_if_no_camera()

        camera = self._cam_manager.get_camera_matching("vimc")

        try:
            camera.configure()  
            camera.create_buffers_and_requests()
            camera.run_cycle()
        finally:
            camera.close()

    def test_get_one_frame(self):
        self._skip_if_no_camera()

        camera = self._cam_manager.get_camera_matching("vimc")

        from PIL import Image
        try:
            camera.configure()  
            camera.create_buffers_and_requests()

            img = camera.get_one_frame()
            # There are seven color bars in the vimc test image
            assert len(set(img[::4, 500, 1].flatten().tolist())) == 7

            Image.fromarray(img).save("test.png")
        finally:
            camera.close()