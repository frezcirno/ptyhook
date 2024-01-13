import atexit
import os
import sys
import time


class Decoder:
    def __init__(self):
        self.buf = b""
        self.last_dir = -1

    def decode(self):
        if len(self.buf) < 1:
            return None
        direction = self.buf[0] >> 7
        if self.buf[0] & 0x40 == 0:
            if len(self.buf) < 1 + 1:
                return None
            size = self.buf[0] & 0x3F
            if len(self.buf) < 1 + size:
                return None
            data = self.buf[1 : 1 + size]
            self.buf = self.buf[1 + size :]
        elif self.buf[0] & 0x20 == 0:
            if len(self.buf) < 2 + 1:
                return None
            size = (self.buf[0] & 0x1F) << 8 | self.buf[1]
            if len(self.buf) < 2 + size:
                return None
            data = self.buf[2 : 2 + size]
            self.buf = self.buf[2 + size :]
        elif self.buf[0] & 0x10 == 0:
            if len(self.buf) < 3 + 1:
                return None
            size = (self.buf[0] & 0x0F) << 16 | self.buf[1] << 8 | self.buf[2]
            if len(self.buf) < 3 + size:
                return None
            data = self.buf[3 : 3 + size]
            self.buf = self.buf[3 + size :]
        elif self.buf[0] & 0x08 == 0:
            if len(self.buf) < 4 + 1:
                return None
            size = (
                (self.buf[0] & 0x07) << 24
                | self.buf[1] << 16
                | self.buf[2] << 8
                | self.buf[3]
            )
            if len(self.buf) < 4 + size:
                return None
            data = self.buf[4 : 4 + size]
            self.buf = self.buf[4 + size :]
        else:
            if len(self.buf) < 5 + 1:
                return None
            size = (
                self.buf[1] << 24 | self.buf[2] << 16 | self.buf[3] << 8 | self.buf[4]
            )
            if len(self.buf) < 5 + size:
                return None
            data = self.buf[5 : 5 + size]
            self.buf = self.buf[5 + size :]
        return direction, data


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <tty_index>")
        exit(1)

    index = int(sys.argv[1])

    os.system("sudo rmmod ptyhook")
    os.system("make && sudo insmod ptyhook.ko tty_index=%d" % index)
    atexit.register(lambda: os.system("sudo rmmod ptyhook"))

    decoder = Decoder()
    fd = open("/proc/ptyhook_data", "rb")

    while True:
        data = fd.read()
        if data:
            decoder.buf += data
            while pkt := decoder.decode():
                if pkt[0] != decoder.last_dir:
                    sys.stdout.buffer.write(b"\n")
                    if pkt[0] == 0:
                        sys.stdout.buffer.write(b">>> ")
                    else:
                        sys.stdout.buffer.write(b"<<< ")
                decoder.last_dir = pkt[0]
                sys.stdout.buffer.write(pkt[1])
                sys.stdout.buffer.flush()
        else:
            time.sleep(0.1)
