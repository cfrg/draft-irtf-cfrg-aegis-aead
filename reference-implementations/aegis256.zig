const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlock = std.crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;

pub const Aegis256 = struct {
    const State = [6]AesBlock;

    s: State,

    inline fn aesround(in: AesBlock, rk: AesBlock) AesBlock {
        return in.encrypt(rk);
    }

    fn update(self: *Aegis256, m: AesBlock) void {
        const s = self.s;
        self.s = State{
            aesround(s[5], s[0].xorBlocks(m)),
            aesround(s[0], s[1]),
            aesround(s[1], s[2]),
            aesround(s[2], s[3]),
            aesround(s[3], s[4]),
            aesround(s[4], s[5]),
        };
    }

    fn init(key: [32]u8, nonce: [32]u8) Aegis256 {
        const c0 = AesBlock.fromBytes(&[16]u8{ 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 });
        const c1 = AesBlock.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd });
        const k0 = AesBlock.fromBytes(key[0..16]);
        const k1 = AesBlock.fromBytes(key[16..32]);
        const n0 = AesBlock.fromBytes(nonce[0..16]);
        const n1 = AesBlock.fromBytes(nonce[16..32]);
        var self = Aegis256{ .s = State{
            k0.xorBlocks(n0),
            k1.xorBlocks(n1),
            c1,
            c0,
            k0.xorBlocks(c0),
            k1.xorBlocks(c1),
        } };
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            self.update(k0);
            self.update(k1);
            self.update(k0.xorBlocks(n0));
            self.update(k1.xorBlocks(n1));
        }
        return self;
    }

    fn enc(self: *Aegis256, xi: *const [16]u8) [16]u8 {
        const s = self.s;
        const z = s[1].xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[2].andBlocks(s[3]));
        const t = AesBlock.fromBytes(xi);
        const ci = t.xorBlocks(z);
        self.update(t);
        return ci.toBytes();
    }

    fn dec(self: *Aegis256, ci: *const [16]u8) [16]u8 {
        const s = self.s;
        const z = s[1].xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[2].andBlocks(s[3]));
        const t = AesBlock.fromBytes(ci);
        const xi = t.xorBlocks(z);
        self.update(xi);
        return xi.toBytes();
    }

    fn decLast(self: *Aegis256, xn: []u8, cn: []const u8) void {
        const s = self.s;
        const z = s[1].xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[2].andBlocks(s[3]));
        var pad = [_]u8{0} ** 16;
        mem.copy(u8, pad[0..cn.len], cn);
        const t = AesBlock.fromBytes(&pad);
        const out = t.xorBlocks(z);
        mem.copy(u8, &pad, &out.toBytes());
        mem.copy(u8, xn, pad[0..cn.len]);
        mem.set(u8, pad[cn.len..], 0);
        const v = AesBlock.fromBytes(&pad);
        self.update(v);
    }

    fn finalize(self: *Aegis256, ad_len: usize, msg_len: usize) [16]u8 {
        var s = &self.s;
        var b: [16]u8 = undefined;
        mem.writeIntLittle(u64, b[0..8], @intCast(u64, ad_len) * 8);
        mem.writeIntLittle(u64, b[8..16], @intCast(u64, msg_len) * 8);
        const t = s[3].xorBlocks(AesBlock.fromBytes(&b));
        var i: usize = 0;
        while (i < 7) : (i += 1) {
            self.update(t);
        }
        return s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).xorBlocks(s[4]).xorBlocks(s[5]).toBytes();
    }

    pub fn encrypt(ct: []u8, msg: []const u8, ad: []const u8, key: [32]u8, nonce: [32]u8) [16]u8 {
        assert(ct.len == msg.len);
        var aegis = init(key, nonce);

        var i: usize = 0;
        while (i + 16 <= ad.len) : (i += 16) {
            _ = aegis.enc(ad[i..][0..16]);
        }
        if (ad.len % 16 != 0) {
            var pad = [_]u8{0} ** 16;
            mem.copy(u8, pad[0 .. ad.len % 16], ad[i..]);
            _ = aegis.enc(&pad);
        }

        i = 0;
        while (i + 16 <= msg.len) : (i += 16) {
            mem.copy(u8, ct[i..][0..16], &aegis.enc(msg[i..][0..16]));
        }
        if (msg.len % 16 != 0) {
            var pad = [_]u8{0} ** 16;
            mem.copy(u8, pad[0 .. msg.len % 16], msg[i..]);
            mem.copy(u8, ct[i..], aegis.enc(&pad)[0 .. msg.len % 16]);
        }

        return aegis.finalize(ad.len, msg.len);
    }

    pub fn decrypt(msg: []u8, ct: []const u8, tag: [16]u8, ad: []const u8, key: [32]u8, nonce: [32]u8) AuthenticationError!void {
        assert(ct.len == msg.len);
        var aegis = init(key, nonce);

        var i: usize = 0;
        while (i + 16 <= ad.len) : (i += 16) {
            _ = aegis.enc(ad[i..][0..16]);
        }
        if (ad.len % 16 != 0) {
            var pad = [_]u8{0} ** 16;
            mem.copy(u8, pad[0 .. ad.len % 16], ad[i..]);
            _ = aegis.enc(&pad);
        }

        i = 0;
        while (i + 16 <= ct.len) : (i += 16) {
            mem.copy(u8, msg[i..][0..16], &aegis.dec(ct[i..][0..16]));
        }
        if (ct.len % 16 != 0) {
            aegis.decLast(msg[i..], ct[i..]);
        }

        const expected_tag = aegis.finalize(ad.len, msg.len);
        if (!crypto.utils.timingSafeEql([expected_tag.len]u8, expected_tag, tag)) {
            return error.AuthenticationFailed;
        }
    }
};
