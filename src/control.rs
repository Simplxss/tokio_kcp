use bytes::{Buf, BufMut, BytesMut};

#[derive(Default, Clone, Debug)]
pub struct ControlSegment {
    pub cmd: u32,
    pub conv: u32,
    pub token: u32,
    pub parm1: u32,
    pub parm2: u32,
}

impl ControlSegment {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(20);
        buf.put_u32(self.cmd);
        buf.put_u32(self.conv);
        buf.put_u32(self.token);
        buf.put_u32(self.parm1);
        buf.put_u32(self.parm2);
        buf
    }

    pub fn decode(buf: &[u8]) -> ControlSegment {
        let mut buf = BytesMut::from(buf);
        let cmd = buf.get_u32();
        let conv = buf.get_u32();
        let token = buf.get_u32();
        let parm1 = buf.get_u32();
        let parm2 = buf.get_u32();
        ControlSegment {
            cmd,
            conv,
            token,
            parm1,
            parm2,
        }
    }
}

pub fn build_handshake_request() -> BytesMut {
    let segment = ControlSegment {
        cmd: 0xff,
        conv: 0,
        token: 0,
        parm1: 0x499602d2,
        parm2: 0xffffffff,
    };
    segment.encode()
}

pub fn build_handshake_response(conv: u32, token: u32) -> BytesMut {
    let segment = ControlSegment {
        cmd: 0x145,
        conv,
        token,
        parm1: 0x499602d2,
        parm2: 0x14514545,
    };
    segment.encode()
}

pub fn build_disconnect_request(conv: u32, token: u32, reason: u32) -> BytesMut {
    let segment = ControlSegment {
        cmd: 0x194,
        conv,
        token,
        parm1: reason,
        parm2: 0x19419494,
    };
    segment.encode()
}

pub fn build_disconnect_response(conv: u32, token: u32) -> BytesMut {
    let segment = ControlSegment {
        cmd: 0x194,
        conv,
        token,
        parm1: 0x3,
        parm2: 0x19419494,
    };
    segment.encode()
}
