#!/bin/bash

# Requires the following apt packages to be installed
# python3-yaml python3-ply python3-jinja2 libgnutls28-dev openssl
# ninja-build pkg-config libboost-dev cmake libgtest-dev meson libdrm-dev
git clone https://github.com/kbingham/libcamera.git

cd libcamera
meson build -Dpipelines=raspberrypi,vimc -Dtest=false -Dv4l2=true
ninja -C build
sudo ninja -C build install
