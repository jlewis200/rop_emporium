FROM ubuntu:20.04
RUN apt update 
RUN apt install -y openssh-server
RUN apt install -y gdbserver
RUN apt install -y gdb
RUN apt install -y python3-pip
RUN apt install -y git
RUN apt install -y strace
RUN apt install -y elfutils
RUN apt install -y dh-autoreconf

RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install pwntools

# install pwndbg
WORKDIR /
RUN git clone https://github.com/pwndbg/pwndbg.git
WORKDIR /pwndbg
RUN ./setup.sh

# install patchelf
WORKDIR /
RUN git clone https://github.com/NixOS/patchelf.git
WORKDIR /patchelf
RUN ./bootstrap.sh
RUN ./configure
RUN make
RUN make check
RUN make install

# install pwninit
WORKDIR /usr/local/bin
RUN wget https://github.com/io12/pwninit/releases/download/3.3.0/pwninit
RUN chmod +x pwninit

RUN useradd -rm -d /home/test -s /bin/bash -g root -G sudo -u 1000 test 
RUN  echo 'test:test' | chpasswd
RUN  echo 'root:root' | chpasswd
WORKDIR /home/test
