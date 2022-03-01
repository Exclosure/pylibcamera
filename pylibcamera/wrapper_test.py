import unittest

import pylibcamera.wrapper


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
        for i in range(3):
            c.close()

    def test_everything(self):
        self._skip_if_no_camera()

        camera = self._cam_manager.get_camera(0)

        camera.configure()  
        camera.create_buffers_and_requests()
        camera.run_cycle()
        camera.close()

