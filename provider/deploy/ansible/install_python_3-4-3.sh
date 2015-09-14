#!/usr/bin/env bash
PY_VERSION=3.4.3
PY_URL="https://www.python.org/ftp/python/$PY_VERSION/Python-$PY_VERSION.tgz"
PY_DIR="Python-$PY_VERSION"

cd $HOME
wget "$PY_URL"
sudo tar -xvf "$PY_DIR.tgz" -C /opt && rm -f "$PY_DIR.tgz"
# Link the headers
sudo ln -s "/opt/$PY_DIR/Include" /usr/include/python3.4
cd "/opt/$PY_DIR"
# Configure and make
./configure --with-ensurepip=install && make
# Install it
sudo make install
touch "/python$PY_VERSION" # create empty file so Ansible can check this script has been run