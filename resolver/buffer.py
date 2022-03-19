from dataclasses import dataclass


@dataclass
class ByteBuffer:
    buf: bytes
    pos: int = 0

    def skip(self, n: int):
        self.pos += n
        return self

    def read_uint8(self):
        result = int.from_bytes(self.buf[self.pos:self.pos + 1], byteorder="big", signed=False)
        self.pos += 1
        return result

    def peek_uint16(self):
        return int.from_bytes(self.buf[self.pos:self.pos + 2], byteorder="big", signed=False)

    def read_uint16(self):
        result = self.peek_uint16()
        self.pos += 2
        return result

    def peek_uint32(self):
        part = self.buf[self.pos:self.pos + 4]
        return int.from_bytes(part, byteorder="big", signed=False)

    def read_uint32(self):
        result = self.peek_uint32()
        self.pos += 4
        return result

    def read_plain(self, num_bytes: int):
        result = self.peek_plain(num_bytes)
        self.pos += num_bytes
        return result

    def peek_plain(self, num_bytes: int):
        return self.buf[self.pos:self.pos + num_bytes].hex()

    # Jumps implemented but not error safe (loop jumps?)
    def read_qname(self):
        result: list[str] = []
        has_jumped = False
        pos_return = -1

        label_length = self.buf[self.pos]
        while label_length > 0:
            self.pos += 1
            if (label_length & 0xC0) == 0xC0:
                if not has_jumped:
                    pos_return = self.pos + 1
                offset1 = label_length
                offset2 = self.buf[self.pos]
                pos_target = ((offset1 ^ 0xC0) << 8) | offset2
                self.pos = pos_target
                has_jumped = True
            else:
                label = self.buf[self.pos:self.pos + label_length].decode()
                result.append(label)
                self.pos += label_length
            label_length = self.buf[self.pos]

        if has_jumped:
            self.pos = pos_return
        else:
            self.pos += 1

        return ".".join(result)
