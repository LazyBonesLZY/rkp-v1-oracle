# RKP V1 Oracle

On-device Google keybox provisioner for Qualcomm KeyMint firmware where `CSR_V2` (TA command `0x3122`) is rejected with `-40`.

Based on the signing-oracle approach from [Kanxue thread-293244](https://bbs.kanxue.com/thread-293244.htm) — but for firmware without the V2 path, this exploits the **PureSoft RKP context's constant HBK** (32 zero bytes) to forge the `keysToSign` MAC, then drives the legacy **V1 AIDL** `generateCertificateRequest` as the oracle:

```
[device]  generate P-256 keypair (private key never leaves the phone)
[device]  forge COSE_Mac0 with HKDF(zeros, "Key to MAC public keys")   <- HBK=0
[device]  IRemotelyProvisionedComponent.generateCertificateRequest(false, [key], eek, challenge)
[Google]  remoteprovisioning.googleapis.com :signCertificates -> 4-cert chain
[device]  keybox.xml (SEC1 PEM private key + leaf-first Google chain)
```

## Files

| Path | Purpose |
|---|---|
| `install.sh` | Installer: extracts the AIDL apk from the device's own `/apex`, deploys the jar, writes `provision.sh` |
| `rkporacle.jar` | The whole pipeline, runs under `app_process` — no PC, no Python |
| `src/` | Java sources: `RkpOracle` (full flow), `CborValue` (minimal CBOR), `Stubs` (reflection) |

## Usage

```sh
# copy this folder to the device, then as root:
su
sh /path/to/rkp-v1-oracle/install.sh

# mint a fresh keybox (~1-2 min, two Google round-trips):
sh /data/local/tmp/rkp-oracle/provision.sh /sdcard/mykeybox
```

Output lands in the given directory:

- `keybox.xml` — Google 4-cert chain (`leaf -> Droid CA3 -> Droid CA2 -> Key Attestation CA1`) + SEC1 private key
- `attest_key_priv.pem` — the matching private key
- `cert_chain.der` — raw DER chain

Install the keybox into whichever keystore module you use (TrickyStore and friends expect it at `/data/adb/<module>/keybox.xml`).

## Device requirements

- Root (KernelSU / Magisk / APatch — anything that gives `su`)
- Qualcomm KeyMint with the **V1 AIDL** `IRemotelyProvisionedComponent` and the PureSoft RKP context (`HBK == 32 zero bytes` firmware class)
- Network access to `remoteprovisioning.googleapis.com` (system proxy / TUN is fine)

## Notes

- Leaf certificates are valid **~15 days**; re-run to mint a fresh one. Every run produces an unrelated new key — revoking one certificate never affects the next.
- The keybox is **device-independent**: the chain carries only the public key hash (no serial/IMEI/model), so it works on any device once installed.
- `NOT_APPROVED` in the `provisionInfo` extension reflects the *signing* device's real bootloader state as reported by its TA. Locked-bootloader devices issue `APPROVED` keyboxes.
- The private key is emitted as **SEC1** (`BEGIN EC PRIVATE KEY`). TrickyStore's `PEMParser` requires this format; PKCS8 causes a silent load failure.
- AIDL proxy classes are loaded from the device's own `/apex` at install time, so the marshalling always matches the local HAL version.

## Credits

- [Kanxue thread-293244](https://bbs.kanxue.com/thread-293244.htm) — the original RKP signing-oracle research
- [Duck ToolBox](https://github.com/eltavine/Duck-ToolBox) — their `CSR_V2` device-issuer covers newer firmware; this repo covers the V1-only class

## License

MIT
