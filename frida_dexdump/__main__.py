# Author: hluwa <hluwa888@gmail.com>
# HomePage: https://github.com/hluwa
# CreateTime: 2021/6/3
import hashlib
import json
import logging
import os.path
import re
import time
from frida_dexdump.agent import DexDumpAgent
from frida_tools.application import ConsoleApplication
from wallbreaker.connection import Connection

from frida_dexdump.banner import show_banner

logger = logging.getLogger("frida-dexdump")
md5 = lambda bs: hashlib.md5(bs).hexdigest()


class SessionConnection(Connection):

    def __init__(self, device, session):
        self.device = device
        self.session = session
        self.process = str(self.session)


class DexDumpApplication(ConsoleApplication):
    agent = None

    def _needs_target(self):
        return True

    def _usage(self):
        return "Usage see: frida-dexdump -h"

    def _add_options(self, parser):
        parser.add_option("-o", "--output", help="select output path",
                          type='string', action='store')
        parser.add_option("-d", "--deep-search", help="enable deep search",
                          action='store_true', dest="enable_deep", default=False)
        parser.add_option("--delay", help="delay many second for start work when spawn, default is 5s",
                          type='int', action='store', default=5)

    def _initialize(self, parser, options, args):
        self.mds = set()
        self.output = options.output
        self.enable_deep = options.enable_deep
        self.delay = options.delay
        if self._target[0] != "file":
            self.delay = 0

    def _start(self):
        self.connection = SessionConnection(self._device, self._session)
        self.agent = DexDumpAgent(self.connection)
        self.package_name = self.get_package_name()
        if not self.output:
            self.output = os.path.join(os.getcwd(), self.package_name.replace(":", "-"))
            os.makedirs(self.output, exist_ok=True)
        self._resume()
        if self.delay:
            logger.info("Delaying {}s".format(self.delay))
            time.sleep(self.delay)
        self.dump()
        self._exit(0)

    def dump(self):
        logger.info("[*] Starting dex search ...")
        st = time.time()
        ranges = self.agent.search_dex(enable_deep_search=self.enable_deep)
        et = time.time()
        logger.info("[*] Found {} dex, use {} time.".format(len(ranges), int(et - st)))
        for dex in ranges:
            try:
                bs = self.agent.memory_dump(dex['addr'], dex['size'])
                md = md5(bs)
                if md in self.mds:
                    continue
                self.mds.add(md)
                bs = fix_header(bs)
                out_path = os.path.join(self.output, dex['addr'] + ".dex")
                with open(out_path, 'wb') as out:
                    out.write(bs)
                logger.info("[*] DexSize={}, DexMd5={}, SavePath={}"
                            .format(hex(dex['size']), md, out_path))
            except Exception as e:
                logger.exception("[-] {}: {}".format(e, dex))

    def get_package_name(self):
        try:
            pid = self._session._impl.pid
            for process in self._device.enumerate_processes():
                if process.pid == pid:
                    return process.name
            return "dexdump.unnamed.{}".format(pid)
        except:
            return "dexdump.unnamed"


def fix_header(dex_bytes):
    import struct
    dex_size = len(dex_bytes)

    if dex_bytes[:4] != b"dex\n":
        dex_bytes = b"dex\n035\x00" + dex_bytes[8:]

    if dex_size >= 0x24:
        dex_bytes = dex_bytes[:0x20] + struct.Struct("<I").pack(dex_size) + dex_bytes[0x24:]

    if dex_size >= 0x28:
        dex_bytes = dex_bytes[:0x24] + struct.Struct("<I").pack(0x70) + dex_bytes[0x28:]

    if dex_size >= 0x2C and dex_bytes[0x28:0x2C] not in [b'\x78\x56\x34\x12', b'\x12\x34\x56\x78']:
        dex_bytes = dex_bytes[:0x28] + b'\x78\x56\x34\x12' + dex_bytes[0x2C:]

    return dex_bytes


def main():
    show_banner()
    logging.basicConfig(level=logging.INFO)
    DexDumpApplication().run()


if __name__ == "__main__":
    main()
