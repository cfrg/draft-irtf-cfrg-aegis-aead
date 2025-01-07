const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlock = std.crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;

pub const Aegis128L = Aegis128L_(128);
pub const Aegis128L_256 = Aegis128L_(256);

fn Aegis128L_(comptime tag_bits: u9) type {
    assert(tag_bits == 128 or tag_bits == 256); // tag bits must be 128 or 256

    return struct {
        const Self = @This();

        pub const key_length = 16;
        pub const nonce_length = 16;
        pub const tag_length: comptime_int = tag_bits / 8;
        pub const ad_max_length = 1 << 61;
        pub const msg_max_length = 1 << 61;
        pub const ct_max_length = msg_max_length + tag_length;

        const State = [8]AesBlock;

        s: State,

        inline fn aesround(in: AesBlock, rk: AesBlock) AesBlock {
            return in.encrypt(rk);
        }

        fn update(self: *Self, m0: AesBlock, m1: AesBlock) void {
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

        fn init(key: [key_length]u8, nonce: [nonce_length]u8) Self {
            const c0 = AesBlock.fromBytes(&[16]u8{ 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 });
            const c1 = AesBlock.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd });
            const key_block = AesBlock.fromBytes(&key);
            const nonce_block = AesBlock.fromBytes(&nonce);
            var self = Self{ .s = State{
                key_block.xorBlocks(nonce_block),
                c1,
                c0,
                c1,
                key_block.xorBlocks(nonce_block),
                key_block.xorBlocks(c0),
                key_block.xorBlocks(c1),
                key_block.xorBlocks(c0),
            } };
            for (0..10) |_| {
                self.update(nonce_block, key_block);
            }
            return self;
        }

        fn absorb(self: *Self, ai: *const [32]u8) void {
            const t0 = AesBlock.fromBytes(ai[0..16]);
            const t1 = AesBlock.fromBytes(ai[16..32]);
            self.update(t0, t1);
        }

        fn enc(self: *Self, xi: *const [32]u8) [32]u8 {
            const s = self.s;
            const z0 = s[1].xorBlocks(s[6]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            const t0 = AesBlock.fromBytes(xi[0..16]);
            const t1 = AesBlock.fromBytes(xi[16..32]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            self.update(t0, t1);
            var ci: [32]u8 = undefined;
            ci[0..16].* = out0.toBytes();
            ci[16..32].* = out1.toBytes();
            return ci;
        }

        fn dec(self: *Self, ci: *const [32]u8) [32]u8 {
            const s = self.s;
            const z0 = s[1].xorBlocks(s[6]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            const t0 = AesBlock.fromBytes(ci[0..16]);
            const t1 = AesBlock.fromBytes(ci[16..32]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            self.update(out0, out1);
            var xi: [32]u8 = undefined;
            xi[0..16].* = out0.toBytes();
            xi[16..32].* = out1.toBytes();
            return xi;
        }

        fn decLast(self: *Self, xn: []u8, cn: []const u8) void {
            const s = self.s;
            const z0 = s[1].xorBlocks(s[6]).xorBlocks(s[2].andBlocks(s[3]));
            const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
            var pad = [_]u8{0} ** 32;
            @memcpy(pad[0..cn.len], cn);
            const t0 = AesBlock.fromBytes(pad[0..16]);
            const t1 = AesBlock.fromBytes(pad[16..32]);
            const out0 = t0.xorBlocks(z0);
            const out1 = t1.xorBlocks(z1);
            pad[0..16].* = out0.toBytes();
            pad[16..32].* = out1.toBytes();
            @memcpy(xn, pad[0..cn.len]);
            @memset(pad[cn.len..], 0);
            const v0 = AesBlock.fromBytes(pad[0..16]);
            const v1 = AesBlock.fromBytes(pad[16..32]);
            self.update(v0, v1);
        }

        fn finalize(self: *Self, ad_len: usize, msg_len: usize) [tag_length]u8 {
            var s = &self.s;
            var b: [16]u8 = undefined;
            mem.writeInt(u64, b[0..8], @as(u64, ad_len) * 8, .little);
            mem.writeInt(u64, b[8..16], @as(u64, msg_len) * 8, .little);
            const t = s[2].xorBlocks(AesBlock.fromBytes(&b));
            for (0..7) |_| {
                self.update(t, t);
            }
            var tag: [tag_length]u8 = undefined;
            if (tag_length == 16) {
                tag = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[6]).toBytes();
            } else {
                tag[0..16].* = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).toBytes();
                tag[16..].* = s[4].xorBlocks(s[5]).xorBlocks(s[6]).xorBlocks(s[7]).toBytes();
            }
            return tag;
        }

        pub fn encrypt(
            ct: []u8,
            msg: []const u8,
            ad: []const u8,
            key: [key_length]u8,
            nonce: [nonce_length]u8,
        ) [tag_length]u8 {
            assert(msg.len <= msg_max_length);
            assert(ad.len <= ad_max_length);
            assert(ct.len == msg.len);
            var aegis = init(key, nonce);

            var i: usize = 0;
            while (i + 32 <= ad.len) : (i += 32) {
                aegis.absorb(ad[i..][0..32]);
            }
            if (ad.len % 32 != 0) {
                var pad = [_]u8{0} ** 32;
                @memcpy(pad[0 .. ad.len % 32], ad[i..]);
                aegis.absorb(&pad);
            }

            i = 0;
            while (i + 32 <= msg.len) : (i += 32) {
                ct[i..][0..32].* = aegis.enc(msg[i..][0..32]);
            }
            if (msg.len % 32 != 0) {
                var pad = [_]u8{0} ** 32;
                @memcpy(pad[0 .. msg.len % 32], msg[i..]);
                @memcpy(ct[i..], aegis.enc(&pad)[0 .. msg.len % 32]);
            }

            return aegis.finalize(ad.len, msg.len);
        }

        pub fn decrypt(
            msg: []u8,
            ct: []const u8,
            tag: [tag_length]u8,
            ad: []const u8,
            key: [key_length]u8,
            nonce: [nonce_length]u8,
        ) AuthenticationError!void {
            assert(ct.len <= ct_max_length);
            assert(ad.len <= ad_max_length);
            assert(ct.len == msg.len);
            var aegis = init(key, nonce);

            var i: usize = 0;
            while (i + 32 <= ad.len) : (i += 32) {
                aegis.absorb(ad[i..][0..32]);
            }
            if (ad.len % 32 != 0) {
                var pad = [_]u8{0} ** 32;
                @memcpy(pad[0 .. ad.len % 32], ad[i..]);
                aegis.absorb(&pad);
            }

            i = 0;
            while (i + 32 <= ct.len) : (i += 32) {
                msg[i..][0..32].* = aegis.dec(ct[i..][0..32]);
            }
            if (ct.len % 32 != 0) {
                aegis.decLast(msg[i..], ct[i..]);
            }

            const expected_tag = aegis.finalize(ad.len, msg.len);
            if (!crypto.utils.timingSafeEql([expected_tag.len]u8, expected_tag, tag)) {
                crypto.utils.secureZero(u8, msg);
                return error.AuthenticationFailed;
            }
        }

        pub fn stream(
            out: []u8,
            key: [key_length]u8,
            nonce: ?[nonce_length]u8,
        ) void {
            assert(out.len <= msg_max_length);
            var aegis = init(key, nonce orelse [_]u8{0} ** nonce_length);

            const zero = [_]u8{0} ** 32;

            var i: usize = 0;
            while (i + 32 <= out.len) : (i += 32) {
                out[i..][0..32].* = aegis.enc(&zero);
            }
            if (out.len % 32 != 0) {
                @memcpy(out[i..], aegis.enc(&zero)[0 .. out.len % 32]);
            }
        }

        pub fn mac(
            data: []const u8,
            key: [key_length]u8,
            nonce: [nonce_length]u8,
        ) [tag_length]u8 {
            assert(data.len <= ad_max_length);
            var aegis = init(key, nonce);

            var i: usize = 0;
            while (i + 32 <= data.len) : (i += 32) {
                aegis.absorb(data[i..][0..32]);
            }
            if (data.len % 32 != 0) {
                var pad = [_]u8{0} ** 32;
                @memcpy(pad[0 .. data.len % 32], data[i..]);
                aegis.absorb(&pad);
            }
            return aegis.finalize(data.len, tag_length);
        }
    };
}
