import io
import zlib
import bisect

from Crypto.Cipher import Salsa20
from terminology import (
    in_bold,
    in_blue,
    in_cyan,
    in_green,
    in_magenta,
    in_red,
    in_yellow,
)


class Cav:
    """
    Code and value (either number or string)
    """

    def __init__(self):
        self.code = 0
        self.number = 0
        self.string = None

    def __str__(self):
        return f"Cav(code={self.code}, number={self.number}, string={self.string!r})"

    def __repr__(self):
        return (
            f"Cav(code={self.code!r}, number={self.number!r}, string={self.string!r})"
        )


class ValueReader:
    ARG_null = 1
    ARG_int = 2
    ARG_text = 3

    code_arg = [0] * 256

    code_arg[0] = ARG_text  # normal text
    code_arg[1] = ARG_text
    code_arg[2] = ARG_text
    code_arg[3] = ARG_text
    code_arg[4] = ARG_text
    code_arg[5] = ARG_text
    code_arg[10] = ARG_null
    code_arg[11] = ARG_null
    code_arg[12] = ARG_null
    code_arg[13] = ARG_null
    code_arg[14] = ARG_null
    code_arg[15] = ARG_null
    code_arg[20] = ARG_text
    code_arg[21] = ARG_text
    code_arg[22] = ARG_text
    code_arg[23] = ARG_text
    code_arg[24] = ARG_text
    code_arg[25] = ARG_text
    code_arg[30] = ARG_null
    code_arg[31] = ARG_null
    code_arg[32] = ARG_null
    code_arg[33] = ARG_null
    code_arg[40] = ARG_int
    code_arg[41] = ARG_int
    code_arg[42] = ARG_text
    code_arg[50] = ARG_text
    code_arg[60] = ARG_text
    code_arg[61] = ARG_text
    code_arg[62] = ARG_text
    code_arg[63] = ARG_text
    code_arg[74] = ARG_text
    code_arg[0xFF] = ARG_null  # EOF marker

    def __init__(self, input_stream):
        self.input = input_stream

    def read(self):
        return self.input.read(1)[0]

    def skip(self, length):
        self.input.read(length)

    def read_raw_string(self, length):
        return self.input.read(length).decode("utf-8")

    def read_string(self):
        return self.read_raw_string(self.read_varint())

    def read_varint(self):
        a = self.read()
        if a < 0xF0:  # 240
            return a
        elif a == 0xFE:  # 254
            return self.read()
        elif a == 0xFD:  # 253
            return 0x100 | self.read()
        elif a == 0xFC:  # 252
            return self.read() << 8 | self.read()
        elif a == 0xFB:  # 251
            return 0x10000 | self.read() << 8 | self.read()
        elif a == 0xFA:  # 250
            return self.read() << 16 | self.read() << 8 | self.read()
        else:
            raise ValueError(f"Invalid varint value: 0x{a:02x}")

    def read_clv(self, cav=None):
        if cav is None:
            cav = Cav()
        cav.code = self.read()
        i = self.code_arg[cav.code]
        if i == 1:
            cav.string = None
            cav.number = 0
        elif i == 2:
            cav.string = None
            cav.number = self.read_varint()
        elif i == 3:
            cav.string = self.read_string()
            cav.number = 0
        else:
            raise ValueError(f"Code not understood: 0x{cav.code:02x}")
        return cav


class Renderer:
    def __init__(self, file_no, offset, acu=None):
        self.file_no = file_no
        self.offset = offset
        if acu is None:
            acu = Acu()
        self.acu = acu
        self.key = bytes.fromhex(
            "ffef8a8d11f535b73cd24fd31ef296d0573ade68b1f079cbdea460149ed4036e"
        )
        self.nonce = bytes.fromhex("fa1f5b7694c268fc")

    def get_desc(self, fn):
        with open(fn, "rb") as f:
            cipher = Salsa20.new(key=self.key, nonce=self.nonce)
            decrypted_data = cipher.decrypt(f.read())
            data = zlib.decompress(decrypted_data, zlib.MAX_WBITS | 16)
            return ValueReader(io.BytesIO(data))

    def render(self):
        res = []
        vr = self.get_desc(f"dictdata/acu_desc_{self.file_no}.s")
        vr.skip(self.offset)

        cav = Cav()
        while True:
            vr.read_clv(cav)
            i = cav.code
            if i == 0xFF:
                break

            if i == 0:
                res.append(cav.string)
            elif i in [1, 3, 5]:
                if i == 5:
                    res.append(in_bold(cav.string))
                else:
                    res.append(in_bold(cav.string))
            elif i == 2:
                res.append(f"/{cav.string}/")
            elif i == 4:
                res.append(in_bold(f"({cav.string})"))
            elif i in [10, 11, 12, 13, 14, 15]:
                if i == 10:
                    res.append(in_bold("Varian"))
                elif i == 11:
                    res.append(in_bold("Dasar"))
                elif i == 12:
                    res.append(in_bold("Gabungan kata"))
                elif i == 13:
                    res.append(in_bold("Kata turunan"))
                elif i == 14:
                    res.append(in_bold("Peribahasa"))
                elif i == 15:
                    res.append(in_bold("Kiasan"))

                res.append(": ")
            elif i in [20, 21, 22, 23, 24, 25]:
                if cav.code == 20:  # kelas
                    res.append(in_red(cav.string))
                elif cav.code == 21:  # bahasa
                    res.append(in_magenta(cav.string))
                elif cav.code == 22:  # bidang
                    res.append(in_yellow(cav.string))
                elif cav.code == 23:
                    res.append(in_cyan(cav.string))
                elif cav.code == 24:
                    res.append(in_green(cav.string))
                elif cav.code == 25:  # ragam
                    res.append(in_blue(cav.string))
            elif i == 74:  # KIMIA + SUB
                res.append(in_green(cav.string))  # sub
            elif cav.code in [30, 31, 32, 33]:
                if cav.code == 30:
                    res.append(in_blue("ki"))
                elif cav.code == 31:
                    res.append(in_blue("kp"))
                elif cav.code == 32:
                    res.append(in_blue("akr"))
                elif cav.code == 33:
                    res.append(in_cyan("ukp"))
            elif cav.code in [40, 41]:
                res.append(in_blue(f"{self.acu.get_acu(cav.number)}"))
                if cav.code == 41:
                    res.append(" » ")
            elif i == 42:
                res.append(in_bold(cav.string))
            elif i == 50:
                res.append(in_green(cav.string))
            elif i in [60, 61, 62, 63]:
                if cav.code == 60:
                    res.append(in_bold(cav.string))
                elif cav.code == 61:
                    res.append(cav.string)  # italic
                elif cav.code == 62:
                    res.append(cav.string)  # sub
                elif cav.code == 63:
                    res.append(cav.string)  # super

        return "".join(res)


class Acu:
    def __init__(self):
        self.offlens = []
        self.acus = []

    def get_acus(self):
        if self.acus:
            return self.acus
        vr = ValueReader(open("dictdata/acu_nilai.txt", "rb"))
        size = vr.read_varint()
        res = [vr.read_raw_string(vr.read()) for i in range(size)]
        self.acus = res
        return res

    def get_offlens(self):
        if self.offlens:
            return self.offlens
        vr = ValueReader(open("dictdata/acu_offlens.txt", "rb"))
        size = vr.read_varint()
        file_no = -1
        offset = 0
        res = [0] * size
        for i in range(size):
            length = vr.read_varint()
            if length == 0xFFFF:
                file_no += 1
                offset = 0
                length = vr.read_varint()
            res[i] = (file_no << 24) | offset
            offset += length
        self.offlens = res
        return res

    def get_acu(self, _id):
        return self.get_acus()[_id - 1]

    def get_id(self, acu):
        pos = bisect.bisect_left(self.get_acus(), acu.lower().strip())
        return max(pos + 1, 0)

    def list_acus(self, prefix):
        acus = self.get_acus()
        prefix = prefix.lower()
        prefix_end = prefix + "\uffff"
        from_idx = bisect.bisect_left(acus, prefix)
        to_idx = bisect.bisect_left(acus, prefix_end)
        from_idx = max(from_idx, 0)
        to_idx = min(to_idx, len(acus))
        return acus[from_idx:to_idx]

    def get_renderer(self, _id):
        offlen = self.get_offlens()[_id - 1]
        return Renderer(offlen >> 24, offlen & 0xFFFFFF, self)


class Completer:
    def __init__(self, acu):
        self.acu = acu
        self.matches = []

    def complete(self, text, state):
        if state == 0:
            self.matches = self.acu.list_acus(text)[:50]
        try:
            return self.matches[state]
        except IndexError:
            return None


def interactive():
    import readline

    acu = Acu()

    readline.set_completer(Completer(acu).complete)
    readline.set_completer_delims("\t\n")
    readline.parse_and_bind("tab: complete")

    while True:
        acu_ = input(in_blue(in_bold("KBBI V> ")))
        id_ = acu.get_id(acu_)
        rend = acu.get_renderer(id_)
        print(rend.render())


def main():
    import sys

    keyword = " ".join(sys.argv[1:])

    if keyword:
        acu = Acu()
        id_ = acu.get_id(keyword)
        rend = acu.get_renderer(id_)
        print(rend.render())
        sys.exit()
    else:
        interactive()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("Interrupted")
