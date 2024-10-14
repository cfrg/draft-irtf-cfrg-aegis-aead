const std = @import("std");

const aegis128l = @import("aegis128l.zig");
const aegis128x = @import("aegis128x.zig");
const aegis256 = @import("aegis256.zig");
const aegis256x = @import("aegis256x.zig");

test {
    const algs = [_]type{
        aegis128l.Aegis128L,
        aegis128x.Aegis128X2,
        aegis128x.Aegis128X4,
        aegis256.Aegis256,
        aegis256x.Aegis256X2,
        aegis256x.Aegis256X4,
        aegis128l.Aegis128L_256,
        aegis128x.Aegis128X2_256,
        aegis128x.Aegis128X4_256,
        aegis256.Aegis256_256,
        aegis256x.Aegis256X2_256,
        aegis256x.Aegis256X4_256,
    };
    inline for (algs) |alg| {
        const key = [_]u8{0x01} ** alg.key_length;
        const nonce = [_]u8{0x02} ** alg.nonce_length;
        const ad = [_]u8{0x03} ** 1000;
        const msg = [_]u8{0x04} ** 1000;
        var msg2: [msg.len]u8 = undefined;
        var ct: [msg.len]u8 = undefined;
        const tag = alg.encrypt(&ct, &msg, &ad, key, nonce);
        try alg.decrypt(&msg2, &ct, tag, &ad, key, nonce);
        try std.testing.expectEqualSlices(u8, &msg, &msg2);
    }
}
