const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlock = std.crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;

pub const Aegis128L = struct {
    const State = [8]AesBlock;

    s: State,

    inline fn aesround(in: AesBlock, rk: AesBlock) AesBlock {
        return in.encrypt(rk);
    }

    fn update(self: *Aegis128L, m0: AesBlock, m1: AesBlock) void {
        const s = self.s;
        self.s = State{
            aesround(s[7], s[0].xorBlocks(m0)),
            aesround(s[0], s[1]),
            aesround(s[1], s[2]),
            aesround(s[2], s[3]),
            aesround(s[3], s[4].xorBlocks(m1)),
            aesround(s[4], s[5]),
            aesround(s[5], s[6]),
            aesround(s[6], s[7]),
        };
    }

    fn init(k: [16]u8, iv: [16]u8) Aegis128L {
        const c0 = AesBlock.fromBytes(&[16]u8{ 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 });
        const c1 = AesBlock.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd });
        const key_block = AesBlock.fromBytes(&k);
        const iv_block = AesBlock.fromBytes(&iv);
        var self = Aegis128L{ .s = State{
            key_block.xorBlocks(iv_block),
            c1,
            c0,
            c1,
            key_block.xorBlocks(iv_block),
            key_block.xorBlocks(c0),
            key_block.xorBlocks(c1),
            key_block.xorBlocks(c0),
        } };
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            self.update(iv_block, key_block);
        }
        return self;
    }

    fn enc(self: *Aegis128L, xi: *const [32]u8) [32]u8 {
        const s = self.s;
        const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
        const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
        const t0 = AesBlock.fromBytes(xi[0..16]);
        const t1 = AesBlock.fromBytes(xi[16..32]);
        const out0 = t0.xorBlocks(z0);
        const out1 = t1.xorBlocks(z1);
        self.update(t0, t1);
        var ci: [32]u8 = undefined;
        mem.copy(u8, ci[0..16], &out0.toBytes());
        mem.copy(u8, ci[16..32], &out1.toBytes());
        return ci;
    }

    fn dec(self: *Aegis128L, ci: *const [32]u8) [32]u8 {
        const s = self.s;
        const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
        const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
        const t0 = AesBlock.fromBytes(ci[0..16]);
        const t1 = AesBlock.fromBytes(ci[16..32]);
        const out0 = t0.xorBlocks(z0);
        const out1 = t1.xorBlocks(z1);
        self.update(out0, out1);
        var xi: [32]u8 = undefined;
        mem.copy(u8, xi[0..16], &out0.toBytes());
        mem.copy(u8, xi[16..32], &out1.toBytes());
        return xi;
    }

    fn decLast(self: *Aegis128L, xn: []u8, cn: []const u8) void {
        const s = self.s;
        const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
        const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
        var pad = [_]u8{0} ** 32;
        mem.copy(u8, pad[0..cn.len], cn);
        const t0 = AesBlock.fromBytes(pad[0..16]);
        const t1 = AesBlock.fromBytes(pad[16..32]);
        const out0 = t0.xorBlocks(z0);
        const out1 = t1.xorBlocks(z1);
        mem.copy(u8, pad[0..16], &out0.toBytes());
        mem.copy(u8, pad[16..32], &out1.toBytes());
        mem.copy(u8, xn, pad[0..cn.len]);
        mem.set(u8, pad[cn.len..], 0);
        const v0 = AesBlock.fromBytes(pad[0..16]);
        const v1 = AesBlock.fromBytes(pad[16..32]);
        self.update(v0, v1);
    }

    fn finalize(self: *Aegis128L, adlen: usize, mlen: usize) [16]u8 {
        var s = &self.s;
        var b: [16]u8 = undefined;
        mem.writeIntLittle(u64, b[0..8], @intCast(u64, adlen) * 8);
        mem.writeIntLittle(u64, b[8..16], @intCast(u64, mlen) * 8);
        const t = s[2].xorBlocks(AesBlock.fromBytes(&b));
        var i: usize = 0;
        while (i < 7) : (i += 1) {
            self.update(t, t);
        }
        return s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[6]).toBytes();
    }

    pub fn encrypt(c: []u8, m: []const u8, ad: []const u8, k: [16]u8, iv: [16]u8) [16]u8 {
        assert(c.len == m.len);
        var aegis = init(k, iv);

        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            _ = aegis.enc(ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0 .. ad.len % 32], ad[i..]);
            _ = aegis.enc(&pad);
        }

        i = 0;
        while (i + 32 <= m.len) : (i += 32) {
            mem.copy(u8, c[i..][0..32], &aegis.enc(m[i..][0..32]));
        }
        if (m.len % 32 != 0) {
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0 .. m.len % 32], m[i..]);
            mem.copy(u8, c[i..], aegis.enc(&pad)[0 .. m.len % 32]);
        }

        return aegis.finalize(ad.len, m.len);
    }

    pub fn decrypt(m: []u8, c: []const u8, tag: [16]u8, ad: []const u8, k: [16]u8, iv: [16]u8) !void {
        assert(c.len == m.len);
        var aegis = init(k, iv);

        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            _ = aegis.enc(ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0 .. ad.len % 32], ad[i..]);
            _ = aegis.enc(&pad);
        }

        i = 0;
        while (i + 32 <= c.len) : (i += 32) {
            mem.copy(u8, m[i..][0..32], &aegis.dec(c[i..][0..32]));
        }
        if (c.len % 32 != 0) {
            aegis.decLast(m[i..], c[i..]);
        }

        const expected_tag = aegis.finalize(ad.len, m.len);
        if (!crypto.utils.timingSafeEql([expected_tag.len]u8, expected_tag, tag)) {
            return error.AuthenticationError;
        }
    }
};
