import mmap
import time
import hashlib

import logging
import numpy as np

import cython
from cython import NULL, size_t

from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp.memory cimport unique_ptr, shared_ptr
from libcpp cimport bool
from libc.stdint cimport uint32_t, uint64_t
from posix.unistd cimport close, read, off_t


cdef extern from "sys/types.h":
    ctypedef dev_t;

cdef extern from "libcamera/libcamera.h" namespace "libcamera":
    ctypedef enum ControlType:
        ControlTypeNone,
        ControlTypeBool,
        ControlTypeByte,
        ControlTypeInteger32,
        ControlTypeInteger64,
        ControlTypeFloat,
        ControlTypeString,
        ControlTypeRectangle,
        ControlTypeSize,

    ctypedef enum StreamRole:
        Raw,
        StillCapture,
        VideoRecording,
        Viewfinder

    ctypedef enum NoiseReductionModeEnum:
        NoiseReductionModeOff = 0,
        NoiseReductionModeFast = 1,
        NoiseReductionModeHighQuality = 2,
        NoiseReductionModeMinimal = 3,
        NoiseReductionModeZSL = 4,

    ctypedef enum CC_Status "libcamera::CameraConfiguration::Status":
        Valid "libcamera::CameraConfiguration::Valid"
        Adjusted "libcamera::CameraConfiguration::Adjusted"
        Invalid "libcamera::CameraConfiguration::Adjusted"

    cdef cppclass Private:
        pass

    cdef cppclass Size:
        unsigned int width;
        unsigned int height;

    cdef cppclass Stream:
        const StreamConfiguration &configuration();

    cdef cppclass ControlId:
        ControlId(unsigned int id, const string &name, ControlType type);
        unsigned int id();
        const string &name();

    cdef cppclass ControlValue:
        pass

    cdef cppclass ControlList:
        # void set(unsigned int id, const ControlValue &value);
        const ControlValue &get(unsigned int id) const;
        bool contains(unsigned int id) const;
        bool empty();
        size_t size();

    cdef struct StreamConfiguration:
        # PixelFormat pixelFormat;
        Size size;
        unsigned int stride;
        unsigned int frameSize;

        unsigned int bufferCount;

        Stream *stream();
        void setStream(Stream *stream)

        string toString();

    ctypedef vector[StreamRole] StreamRoles;

    # Request status (NB: Name shifted from libcamera)
    ctypedef enum Rq_Status "libcamera::Request::Status":
        RequestPending "libcamera::Request::RequestPending"
        RequestComplete "libcamera::Request::RequestComplete"
        RequestCancelled "libcamera::Request::RequestCancelled"

    # Request reuse flag
    ctypedef enum ReuseFlag "libcamera::Request::ReuseFlag":
        Default "libcamera::Request::Default"
        ReuseBuffers "libcamera::Request::ReuseBuffers"

    cdef cppclass Request:
        uint32_t sequence();
        uint64_t cookie();
        Rq_Status status();
        void reuse(ReuseFlag flags);
        ControlList &controls()
        ControlList &metadata()
        # const BufferMap &buffers() const { return bufferMap_; }
        int addBuffer(const Stream *stream, FrameBuffer *buffer)
        # std::unique_ptr<Fence> fence = nullptr);
        FrameBuffer *findBuffer(const Stream *stream);

    cdef cppclass SharedFD:
        # explicit SharedFD(const int &fd = -1);
        # explicit SharedFD(int &&fd);
        # explicit SharedFD(UniqueFD fd);
        # SharedFD(const SharedFD &other);
        # SharedFD(SharedFD &&other);
        # ~SharedFD();
          
        # SharedFD &operator=(const SharedFD &other);
        # SharedFD &operator=(SharedFD &&other);

        bool isValid()
        int get()
        # UniqueFD dup() const;


    ctypedef struct Plane "libcamera::FrameBuffer::Plane":
        unsigned int kInvalidOffset
        SharedFD fd
        unsigned int offset
        unsigned int length

    cdef cppclass FrameBuffer:
        FrameBuffer(const vector[Plane] &planes, unsigned int cookie = 0);
        FrameBuffer(unique_ptr[Private] d, const vector[Plane] &planes, unsigned int cookie = 0);

        const vector[Plane] &planes()
        Request *request() const
        const FrameMetadata &metadata()
        unsigned int cookie()
        void setCookie(unsigned int cookie)
        # unique_ptr[Fence] releaseFence();
        void cancel()

    # In FrameMetadata
    # ctypedef struct Plane:
    #     unsigned int bytesused;

    # In FrameMetadata (NB: Name change)
    ctypedef enum FM_Status "libcamera::FrameMetadata::Status":
        FrameSuccess "libcamera::FrameMetadata::FrameSuccess"
        FrameError "libcamera::FrameMetadata::FrameError"
        FrameCancelled "libcamera::FrameMetadata::FrameCancelled"

    ctypedef struct FrameMetadata:
        FM_Status status;
        unsigned int sequence;
        uint64_t timestamp;

        # Span[Plane] planes()
        # Span[const Plane] planes();

    cdef cppclass FrameBufferAllocator:
        FrameBufferAllocator(shared_ptr[Camera] camera);
        # ~FrameBufferAllocator();

        int allocate(Stream *stream);
        int free(Stream *stream);

        bool allocated();
        const vector[unique_ptr[FrameBuffer]] &buffers(Stream *stream);

    # ctypedef ReqFunc void(*func)(Request *request)

    cdef cppclass Signal[R]:
        Signal()
        void connect( void (*f_ptr)(R* req) )
        void disconnect( void (*f_ptr)(R* req) )

    cdef cppclass Camera:
        int acquire();
        int release();

        int start(const ControlList *controls);
        int stop();
        int configure();
        string id() const;

        # NOTE(meawoppl) - Sketchy: this is defined in libcamera as `using StreamRoles = std::vector<StreamRole>;`
        unique_ptr[CameraConfiguration] generateConfiguration(const vector[StreamRole] &roles);
        int configure(CameraConfiguration *config);
        const ControlList &properties() const;
        unique_ptr[Request] createRequest(uint64_t cookie = 0);
        int queueRequest(Request *request);
        Signal[Request] requestCompleted;

    cdef cppclass CameraManager:
        CameraManager();
        # ~CameraManager();

        vector[shared_ptr[Camera]] cameras() const;
        string version();

        int start();
        void stop();
        Camera get(dev_t devnum);

    cdef cppclass CameraConfiguration:
        int start();
        void stop();
        int size();
        StreamConfiguration &at(unsigned int index);
        CC_Status validate();


cdef class PyCameraManager:
    """
    This class wraps the camera manager surface of libcamera
    NB: The application should only ever init this -ONCE-
    TODO(meawoppl) - singleton whatnot to protect users
    """
    cdef CameraManager* cm;

    def __cinit__(self):
        self.cm = new CameraManager()
        
        logging.info(f"libcamera version: {self.version()}")

        rval = self.cm.start()
        assert rval == 0, f"Camera Manager did not start {rval}"

        n_cameras = self.cm.cameras().size()
       
        logging.info(f"# Cameras Detected: {n_cameras}")
        cams = self.cm.cameras()
        i = 0
        for c in cams:
            logging.info(f"- ({i}) {c.get().id().decode()}")
            i += 1

    def version(self):
        return self.cm.version().decode()

    def get_camera_names(self):
        names = []
        cams = self.cm.cameras()
        for c in cams:
            names.append(c.get().id().decode())
        return names

    def get_n_cameras(self):
        """
        Return the number of cameras that this library
        can access.
        """
        return self.cm.cameras().size()

    def get_camera(self, int index):
        """
        Return a wrapped libcamera driven device based on the index specified
        """
        # TODO(meawoppl) This feels gross
        cdef PyCamera pc = PyCamera.__new__(PyCamera)
        pc._camera = self.cm.cameras()[index]
        return pc 

    def close(self):
        """
        Close and deallocate camera manager resources.
        Attempts to use the class after calling this method
        will almost certainly fail.
        """
        if self.cm != NULL:
            self.cm.stop()
            self.cm = NULL
            logging.info("Stopped camera manager")

    def close(self):
        if self.cm != NULL:
            self.cm.stop()
            self.cm = NULL
            logging.info("Stopped camera manager")

    def __dealloc__(self):
        self.close()


@cython.ccall
@cython.returns(cython.void)
cdef void cpp_cb(Request* request):
    logging.warn("Got a callback!!!")


cdef class PyCamera:
    cdef shared_ptr[Camera] _camera;
    cdef unique_ptr[CameraConfiguration] _camera_cfg;
    cdef StreamConfiguration stream_cfg;
    cdef FrameBufferAllocator* allocator;
    cdef vector[FrameBuffer*]* buffers;
    cdef vector[unique_ptr[Request]]* requests;

    mmaps = {};
    images = [];
   
    def __cinit__(self):
        self.buffers = new vector[FrameBuffer*]()
        self.requests = new vector[unique_ptr[Request]]()

    def configure(self):
        assert self._camera != NULL

        camera_name = self._camera.get().id().decode()
        logging.info(f"Configuration underway for: {camera_name}")
        
        self._camera.get().acquire()
        # Generate a configuration that support raw stills
        # NOTE(meawoppl) - the example I am following uses this, but lib barfs when I add "StillCapture" and "Raw", so IDK
        # self.config = self.camera.generateConfiguration([StreamRole.StillCapture, StreamRole.Raw])   
        self._camera_cfg = self._camera.get().generateConfiguration([StreamRole.StillCapture])   
        assert self._camera_cfg.get() != NULL

        n_cam_configs = self._camera_cfg.get().size()
        logging.info(f"# Camera Stream Configurations: {n_cam_configs}")
        for i in range(n_cam_configs):
            cfg = self._camera_cfg.get().at(i)
            logging.info(f"Config #{i} - '{cfg.toString().c_str()}'")  

        # TODO(meawoppl) change config settings before camera.configre()
        assert self._camera_cfg.get().validate() == CC_Status.Valid
        assert self._camera.get().configure(self._camera_cfg.get()) >= 0

        logging.info("Using stream config #0")
        self.stream_cfg = self._camera_cfg.get().at(0)
        
    def create_buffers_and_requests(self):
        assert self.allocator == NULL
        self.allocator = new FrameBufferAllocator(self._camera)

        logging.info("Allocating buffers")
        # Allocate buffers for the camera/stream pair
        
        assert self.allocator.allocate(self.stream_cfg.stream()) >= 0, "Buffers did not allocate?"
        assert self.allocator.allocated(), "Buffers did not allocate?"

        # The unique_ptr make it so we can't reify this object...
        n_buffers = self.allocator.buffers(self.stream_cfg.stream()).size()
        logging.info(f"{n_buffers} buffers allocated")
        for buff_num in range(n_buffers):
            # Create the buffer for the request
            self.buffers.push_back(self.allocator.buffers(self.stream_cfg.stream()).at(buff_num).get())
            b = self.buffers.back()

            # Extract its memory maps
            n_planes = b.planes().size()
            for plane_num in range(n_planes):
                plane_fd = b.planes().at(plane_num).fd.get()
                plane_off = b.planes().at(plane_num).offset
                plane_len = b.planes().at(plane_num).length
                logging.info(f"Buffer #{buff_num} Plane #{plane_num} FD: {plane_fd} Offset: {plane_off} Len: {plane_len}")

                if plane_fd not in self.mmaps:
                    self.mmaps[plane_fd] = mmap.mmap(
                        plane_fd,
                        plane_len,
                        flags=mmap.MAP_SHARED,
                        prot=mmap.PROT_WRITE|mmap.PROT_READ,
                        access=mmap.ACCESS_DEFAULT,
                        offset=plane_off)

            # Create the request for the buffer and load it in.
            self.requests.push_back(self._camera.get().createRequest())
            self.requests.back().get().addBuffer(self.stream_cfg.stream(), self.buffers.back())

        self.dump_mmaps()

    def dump_mmaps(self):
        logging.info("Created memory maps:")
        for fd, mp in self.mmaps.items():
            h = hashlib.sha256(mp)
            logging.info(f"FD:{fd} = {mp} hash: {h.hexdigest()}")

    def run_cycle(self):
        logging.info("Starting camera")
        self._camera.get().start(NULL)
        
        logging.info("Setup callback")
        # logging.info(self._camera.get().requestCompleted.connect)
        self._camera.get().requestCompleted.connect(cpp_cb)
        
        #self.camera.get().requestCompleted[0].connect(cpp_cb)

        for i in range(self.requests.size()):
            logging.info(f"Queueing request {i}")
            self._camera.get().queueRequest(self.requests.at(i).get())

        # time.sleep(10)

        for i in range(20):
            if any(self.requests.at(r).get().status() == RequestComplete for r in range(self.requests.size())):
                break
            time.sleep(0.1)

        # logging.info("Memory maps hashes:")
        # for fd, mp in self.mmaps.items():
        #     h = hashlib.sha256(mp)
        #     logging.info(f"FD:{fd} = {mp} hash: {h.hexdigest()}")

        #     self.images.append(np.frombuffer(mp).copy())

        self._camera.get().stop()
        logging.info("Stopped camera")

    def close(self):
        if self.allocator != NULL:
            assert self.allocator.free(self.stream_cfg.stream()) >= 0, "Couldn't deallocate buffers?"
            self.allocator = NULL

        if self._camera.get() != NULL:
            self._camera.get().release()
            logging.info("Released Camera")


    def __dealloc__(self):
        self.close()