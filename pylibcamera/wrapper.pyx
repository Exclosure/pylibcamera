import mmap
import time
import hashlib
import logging
import threading
import struct

import numpy as np

import zmq
import cython
from cython import NULL, size_t

from libc.stdint cimport uint32_t, uint64_t

from libcpp cimport bool
from libcpp.memory cimport unique_ptr, shared_ptr
from libcpp.pair cimport pair
from libcpp.string cimport string
from libcpp.unordered_map cimport unordered_map
from libcpp.vector cimport vector

from posix.unistd cimport close, read, off_t


cdef extern from "unistd.h":
    int usleep(unsigned)


cdef extern from "sys/types.h":
    ctypedef dev_t;

cdef extern from "zmq.h":
    void *zmq_ctx_new ();
    int zmq_ctx_term(void *context_);
    int zmq_ctx_shutdown (void *context_);
    int zmq_ctx_set(void *context_, int option_, int optval_);
    int zmq_ctx_get(void *context_, int option_);
    void *zmq_socket (void *, int type_);
    int zmq_close(void *s_);
    int zmq_setsockopt (void *s_, int option_, const void *optval_, size_t optvallen_);
    int zmq_getsockopt (void *s_, int option_, void *optval_, size_t *optvallen_);
    int zmq_bind(void *s_, const char *addr_);
    int zmq_connect(void *s_, const char *addr_);
    int zmq_unbind(void *s_, const char *addr_);
    int zmq_disconnect (void *s_, const char *addr_);
    int zmq_send(void *s_, const void *buf_, size_t len_, int flags_);
    int zmq_send_const (void *s_, const void *buf_, size_t len_, int flags_);
    int zmq_recv(void *s_, void *buf_, size_t len_, int flags_);
    int zmq_socket_monitor (void *s_, const char *addr_, int events_);

    int ZMQ_VERSION_MAJOR 
    int ZMQ_VERSION_MINOR
    int ZMQ_VERSION_PATCH

    int ZMQ_PAIR
    int ZMQ_PUB
    int ZMQ_SUB
    int ZMQ_REQ
    int ZMQ_REP
    int ZMQ_DEALER
    int ZMQ_ROUTER
    int ZMQ_PULL
    int ZMQ_PUSH
    int ZMQ_XPUB
    int ZMQ_XSUB 
    int ZMQ_STREAM 

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

    cdef cppclass Control:
        Control(unsigned int id, const char *name)
        unsigned int id();
        const string &name();

    cdef cppclass ControlId:
        ControlId(unsigned int id, const string &name, ControlType type);
        unsigned int id();
        const string &name();

    cdef cppclass ControlValue:
        ControlValue()
        ControlValue(const ControlValue &other);
        ControlValue &operator=(const ControlValue &other);

        ControlType type();
        bool isNone();
        bool isArray();
        size_t numElements();
        # Span<const uint8_t> data();
        string toString() const;

    cdef cppclass ControlListMap(unordered_map[unsigned int, ControlValue]):
        pass

    cdef cppclass ControlList:
        ControlList()
        # void set(unsigned int id, const ControlValue &value);
        bool contains(unsigned int id) const;
        bool empty();
        size_t size();
        const ControlValue &get(unsigned int id);
        const ControlInfoMap* infoMap();
        # cppclass iterator:
        #     Control& operator*()
        #     iterator operator++()

    cdef cppclass ControlInfo:
        ControlInfo(ControlValue &min, ControlValue &max, ControlValue &default);
        # ControlInfo(Span<const ControlValue> values, const ControlValue &def);
        # ControlInfo(std::set<bool> values, bool def);
        ControlInfo(bool value);

        ControlValue &min();
        ControlValue &max();
        # ControlValue &def(); # Really unsure how to wrap this one...
        vector[ControlValue] &values();

        string toString();

        bool operator==(const ControlInfo &other);
        bool operator!=(const ControlInfo &other);

    cdef cppclass ControlInfoMap(unordered_map[const ControlId*, ControlInfo]):
        ControlInfoMap();
        ControlInfoMap(const ControlInfoMap &other);
        cppclass iterator:
            pair[const ControlId*, ControlInfo]& operator*()
            iterator& operator++()

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
        uint32_t sequence() const;
        uint64_t cookie() const;
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
        unique_ptr[Request] createRequest(uint64_t cookie);
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

    _log = logging.getLogger(__name__)

    def __cinit__(self):
        self.cm = new CameraManager()
        
        self._log.info(f"libcamera version: {self.version()}")

        rval = self.cm.start()
        assert rval == 0, f"Camera Manager did not start {rval}"

        n_cameras = self.cm.cameras().size()
       
        self._log.info(f"# Cameras Detected: {n_cameras}")
        cams = self.cm.cameras()
        i = 0
        for c in cams:
            self._log.info(f"- ({i}) {c.get().id().decode()}")
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

from libc.stdlib cimport rand
from libc.stdio cimport printf, fflush, stdout, stderr, fprintf

cdef char* ipc_address = "ipc://.frame_notif"


# cdef object pycbfunc
@cython.ccall
@cython.returns(cython.void)
@cython.nogil
cdef void cpp_cb(Request* request):
    """
    This method is a shim between the C++ world and Python.
    It uses zmq to send an IPC message to another process.
    This indirection is needed as the libcamera callback
    is triggered inside a thread without the ability to
    access the GIL apropriately. Attempts to access the
    GIL or python objects results in very
    confusing SegFault/SIGABRT calls boiling up at nearly
    random times in the call stack.

    This function is pure C, and serialized a message that
    contains a pair of ints, which are the frame sequence
    number and the cookie respectively.

    These can be used on the python side to capture which
    frame buffer has been populted as a result of requests
    that have been completed.
    """

    # usleep(rand() % 300)

    if request.status() == RequestCancelled:
        fprintf( stderr, "Cancelled Request sequence #%i)\n", request.sequence());
        return

    cdef void* ctx = zmq_ctx_new()
    cdef void* skt = zmq_socket(ctx, ZMQ_REQ)

    cdef int err
    err = zmq_connect(skt, "ipc://.frame_notif")
    if err:
        fprintf( stderr, "Failed to connect to ZMQ socket (%i)\n", err);
        return
    
    cdef int zero = 0
    cdef int nbytes = 8;
    cdef int s[2]
    s[0] = request.sequence()
    s[1] = request.cookie()

    # zmq_send returns the # of bytes sent..
    err = zmq_send(skt, s, nbytes, zero)
    if err != nbytes:
        fprintf(stderr, "Failed to send message (%i)\n", err)

    cdef char[2] ok;
    err = zmq_recv(skt, ok, 2, 0)
    if err != 2:
        fprintf(stderr, "Did not recv() bytes?")

    # # Will linger until messages are sent
    err = zmq_close(skt)
    if err != zero:
        fprintf(stderr, "Error in socket close (%i)\n", err)

    err = zmq_ctx_shutdown(ctx)
    if err != zero:
        fprintf(stderr, "Error in ctx term (%i)\n", err)


from pylibcamera.callback import CallbackManager

cdef class PyCamera:
    cdef shared_ptr[Camera] _camera
    cdef unique_ptr[CameraConfiguration] _camera_cfg
    cdef StreamConfiguration stream_cfg
    cdef FrameBufferAllocator* allocator
    cdef vector[FrameBuffer*]* buffers
    cdef vector[unique_ptr[Request]]* requests

    mmaps = []
    mmaps_by_fd = {}
    images = []

    _log = logging.getLogger(__name__)

    def __cinit__(self):
        self.buffers = new vector[FrameBuffer*]()
        self.requests = new vector[unique_ptr[Request]]()

    def configure(self):
        assert self._camera != NULL

        camera_name = self._camera.get().id().decode()
        self._log.info(f"Configuration underway for: {camera_name}")
        
        self._camera.get().acquire()
        # Generate a configuration that support raw stills
        # NOTE(meawoppl) - the example I am following uses this, but lib barfs when I add "StillCapture" and "Raw", so IDK
        # self.config = self.camera.generateConfiguration([StreamRole.StillCapture, StreamRole.Raw])   
        self._camera_cfg = self._camera.get().generateConfiguration([StreamRole.StillCapture])   
        assert self._camera_cfg.get() != NULL

        n_cam_configs = self._camera_cfg.get().size()
        self._log.info(f"# Camera Stream Configurations: {n_cam_configs}")
        for i in range(n_cam_configs):
            cfg = self._camera_cfg.get().at(i)
            self._log.info(f"Config #{i} - '{cfg.toString().c_str()}'")  

        # TODO(meawoppl) change config settings before camera.configre()
        assert self._camera_cfg.get().validate() == CC_Status.Valid
        assert self._camera.get().configure(self._camera_cfg.get()) >= 0

        self._log.info("Using stream config #0")
        self.stream_cfg = self._camera_cfg.get().at(0)
    
    def dump_controls(self):
        assert self._camera != NULL
        
        # m = self._camera.get().properties().infoMap()
        # for v in m.begin():
        #     cython.cast(cython.uint, v.first)

        # for k, v in [0]:
        #     print(k, v)
        # n_controls = cl.size()
        # for n in range(n_controls):
        #     self._log.info(cl.get(n).toString())

    def create_buffers_and_requests(self):
        assert self.allocator == NULL
        self.allocator = new FrameBufferAllocator(self._camera)

        # Allocate buffers for the camera/stream pair
        self._log.info("Allocating buffers")
        assert self.allocator.allocate(self.stream_cfg.stream()) >= 0, "Buffers did not allocate?"
        assert self.allocator.allocated(), "Buffers did not allocate?"

        # The unique_ptr make it so we can't reify this object...
        n_buffers = self.allocator.buffers(self.stream_cfg.stream()).size()
        logging.info(f"{n_buffers} buffers allocated")
        for buff_num in range(n_buffers):
            # Create the buffer for the request
            self.buffers.push_back(self.allocator.buffers(self.stream_cfg.stream()).at(buff_num).get())
            b = self.buffers.back()
            b.setCookie(buff_num)
            assert b.cookie() == buff_num

            # Extract its memory maps
            n_planes = b.planes().size()
            for plane_num in range(n_planes):
                plane_fd = b.planes().at(plane_num).fd.get()
                plane_off = b.planes().at(plane_num).offset
                plane_len = b.planes().at(plane_num).length
                self._log.info(f"Buffer #{buff_num} Plane #{plane_num} FD: {plane_fd} Offset: {plane_off} Len: {plane_len}")

                if plane_fd not in self.mmaps_by_fd:
                    mp = mmap.mmap(
                        plane_fd,
                        plane_len,
                        flags=mmap.MAP_SHARED,
                        prot=mmap.PROT_WRITE|mmap.PROT_READ,
                        access=mmap.ACCESS_DEFAULT,
                        offset=plane_off)
                    self.mmaps.append(mp)
                    self.mmaps_by_fd[plane_fd] = mp

            # Create the request for the buffer and load it in.
            self.requests.push_back(self._camera.get().createRequest(buff_num))
            self.requests.back().get().addBuffer(self.stream_cfg.stream(), self.buffers.back())

        self.dump_mmaps()

    def dump_mmaps(self):
        self._log.info("Created memory maps:")
        for fd, mp in self.mmaps_by_fd.items():
            h = hashlib.sha256(mp)
            self._log.info(f"MMAP({id(mp)} FD:{fd} hash: {h.hexdigest()}")

    def wrap_on_frame_callback(self, call: callable):
        def fb_call_and_recycle(raw_data):
            sequence, index = struct.unpack("II", raw_data)
            self._log.debug("Triggering frame CB")
            cdef Request* req = self.requests.at(index).get()
            req_status = req.status()
            if req_status != RequestComplete:
                # These should be screened out in the cpp call...
                self._log.warning("Request status not complete: %i", req_status)
            else:
                call(sequence, self.mmaps[index])
                self._log.debug("Frame CB complete")
            req.reuse(ReuseBuffers)
            self._camera.get().queueRequest(req)

        return fb_call_and_recycle

    def log_zmq_version(self):
        self._log.info(f"C ZMQ Version {ZMQ_VERSION_MAJOR}.{ZMQ_VERSION_MINOR}.{ZMQ_VERSION_PATCH}")


    def run_cycle(self):
        self.log_zmq_version()
        logging.info("Starting camera")
        self._camera.get().start(NULL)

        logging.info("Starting CallbackManager")
        cbm = CallbackManager()

        wrapped_cb = self.wrap_on_frame_callback(lambda *args: self._log.info("Callback with %s", repr(args)))
        cbm.add_callback(wrapped_cb)
        cbm.start_callback_thread()      

        logging.info("Setup callback")
        self._camera.get().requestCompleted.connect(cpp_cb)    

        for i in range(self.requests.size()):
            logging.info(f"Queueing request {i}")
            self._camera.get().queueRequest(self.requests.at(i).get())

        if False:
            for i in range(20):
                self._log.debug("Polling requests")
                for r in range(self.requests.size()):
                    status = self.requests.at(r).get().status()
                    self._log.debug("Request %i, status: %i", r, status)
                
                time.sleep(0.1)
        else:
            time.sleep(5)
        
        # logging.info("Memory maps hashes:")
        # for fd, mp in self.mmaps_by_fd.items():
        #     h = hashlib.sha256(mp)
        #     logging.info(f"FD:{fd} = {mp} hash: {h.hexdigest()}")

        #     self.images.append(np.frombuffer(mp).copy())

        self._camera.get().stop()
        cbm.stop_callback_thread()
        self._log.info("Stopped camera")

    def close(self):
        if self.allocator != NULL:
            assert self.allocator.free(self.stream_cfg.stream()) >= 0, "Couldn't deallocate buffers?"
            self.allocator = NULL

        if self._camera.get() != NULL:
            self._camera.get().release()
            self._log.info("Released Camera")


    def __dealloc__(self):
        self.close()