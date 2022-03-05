import os
from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

ext = Extension(
    'pylibcamera.wrapper', 
    sources=["pylibcamera/wrapper.pyx"],
    include_dirs = ["/usr/local/include/libcamera"],
    library_dirs = ["/usr/local/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu/"],
    libraries=["camera", "zmq"],
    extra_compile_args= ["-std=c++17"],
    language="c++")

gdb_debug = os.environ.get('GDB_DEBUG') is not None

setup(name="pylibcamera", ext_modules = cythonize([ext], gdb_debug=gdb_debug))
