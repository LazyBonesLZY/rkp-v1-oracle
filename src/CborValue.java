package rkp;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/** Minimal CBOR value + parser preserving raw encoding. */
public class CborValue {
    public final int major;
    public final Object value;   // Long / byte[] / String / List<CborValue> / Pair for maps
    public final byte[] raw;

    public static class Pair { public final CborValue key, val;
        Pair(CborValue k, CborValue v){key=k;val=v;} }

    CborValue(int major, Object value, byte[] raw) {
        this.major = major; this.value = value; this.raw = raw;
    }

    public long asInt() { return (Long) value; }
    public byte[] asBytes() { return (byte[]) value; }
    public String asText() { return (String) value; }
    @SuppressWarnings("unchecked")
    public CborValue[] asArray() {
        List<CborValue> l = (List<CborValue>) value;
        return l.toArray(new CborValue[0]);
    }
    @SuppressWarnings("unchecked")
    public Pair[] asMap() {
        List<Pair> l = (List<Pair>) value;
        return l.toArray(new Pair[0]);
    }
    public byte[] encode() { return raw.clone(); }

    public static class CborParser {
        private final byte[] buf; private int pos;
        public CborParser(byte[] b) { buf = b; }

        public static CborValue parse(byte[] b) {
            return new CborParser(b).parseOne();
        }

        CborValue parseOne() {
            int start = pos;
            int ib = buf[pos++] & 0xff;
            int major = ib >> 5;
            long info = ib & 0x1f;
            if (info == 24) info = buf[pos++] & 0xff;
            else if (info == 25) { info = ((buf[pos] & 0xff) << 8) | (buf[pos+1] & 0xff); pos += 2; }
            else if (info == 26) { info = ((long)(buf[pos] & 0xff) << 24) | ((buf[pos+1] & 0xff) << 16)
                    | ((buf[pos+2] & 0xff) << 8) | (buf[pos+3] & 0xff); pos += 4; }
            else if (info >= 28) throw new RuntimeException("unsupported cbor info " + info);

            switch (major) {
                case 0: return finish(major, info, start);
                case 1: return finish(major, -1 - info, start);
                case 2: { byte[] b = new byte[(int) info];
                    System.arraycopy(buf, pos, b, 0, (int) info); pos += info;
                    return finish(major, b, start); }
                case 3: { byte[] b = new byte[(int) info];
                    System.arraycopy(buf, pos, b, 0, (int) info); pos += info;
                    return finish(major, new String(b, java.nio.charset.StandardCharsets.UTF_8), start); }
                case 4: { List<CborValue> l = new ArrayList<>();
                    for (long i = 0; i < info; i++) l.add(parseOne());
                    return finish(major, l, start); }
                case 5: { List<Pair> m = new ArrayList<>();
                    for (long i = 0; i < info; i++) {
                        CborValue k = parseOne(); CborValue v = parseOne();
                        m.add(new Pair(k, v));
                    }
                    return finish(major, m, start); }
                case 7: return finish(major, info == 20 ? Boolean.FALSE : Boolean.TRUE, start);
                default: throw new RuntimeException("bad major " + major);
            }
        }

        CborValue finish(int major, Object v, int start) {
            byte[] raw = new byte[pos - start];
            System.arraycopy(buf, start, raw, 0, raw.length);
            return new CborValue(major, v, raw);
        }
    }
}
