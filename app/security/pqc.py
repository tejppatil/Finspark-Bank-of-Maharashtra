"""Post-quantum crypto provider abstraction — resilient, compiler-free.

Everything else in Prahari calls only these six functions; the underlying
provider is selected at import time in order of preference:

  1. liboqs-python (native C, fastest) — used if the shared library is present.
  2. kyber-py + dilithium-py (PURE PYTHON) — installs as plain wheels on any
     machine with no C compiler / cmake, so every teammate's laptop can run the
     demo. This is the default that makes the project portable.

Both provide the SAME NIST-standardized algorithms:
  KEM:       ML-KEM-768  (FIPS 203, a.k.a. Kyber)
  Signature: ML-DSA-65   (FIPS 204, a.k.a. Dilithium)

Import never raises for a missing native toolchain — it just falls back.
"""

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"


def _load_liboqs():
    """Native liboqs — only succeeds if the compiled shared library exists."""
    import oqs  # raises ImportError (not installed) or RuntimeError (no shared lib)

    def kem_keypair():
        with oqs.KeyEncapsulation(KEM_ALG) as k:
            pub = k.generate_keypair()
            return pub, k.export_secret_key()

    def kem_encapsulate(public_key):
        with oqs.KeyEncapsulation(KEM_ALG) as k:
            return k.encap_secret(public_key)  # (ciphertext, shared_secret)

    def kem_decapsulate(secret_key, ciphertext):
        with oqs.KeyEncapsulation(KEM_ALG, secret_key=secret_key) as k:
            return k.decap_secret(ciphertext)

    def sig_keypair():
        with oqs.Signature(SIG_ALG) as s:
            pub = s.generate_keypair()
            return pub, s.export_secret_key()

    def sign(secret_key, message):
        with oqs.Signature(SIG_ALG, secret_key=secret_key) as s:
            return s.sign(message)

    def verify(public_key, message, signature):
        with oqs.Signature(SIG_ALG) as s:
            return s.verify(message, signature, public_key)

    # smoke test — proves the native library actually loaded and works
    pub, sec = kem_keypair()
    ct, ss = kem_encapsulate(pub)
    assert kem_decapsulate(sec, ct) == ss
    return f"liboqs {oqs.oqs_version()} (native C)", (
        kem_keypair, kem_encapsulate, kem_decapsulate, sig_keypair, sign, verify)


def _load_pure_python():
    """Pure-Python ML-KEM-768 + ML-DSA-65 — no compiler, installs everywhere."""
    from kyber_py.ml_kem import ML_KEM_768
    from dilithium_py.ml_dsa import ML_DSA_65

    def kem_keypair():
        ek, dk = ML_KEM_768.keygen()            # (encapsulation/public, decapsulation/secret)
        return ek, dk

    def kem_encapsulate(public_key):
        shared, ct = ML_KEM_768.encaps(public_key)
        return ct, shared                       # normalize to (ciphertext, shared_secret)

    def kem_decapsulate(secret_key, ciphertext):
        return ML_KEM_768.decaps(secret_key, ciphertext)

    def sig_keypair():
        pk, sk = ML_DSA_65.keygen()
        return pk, sk

    def sign(secret_key, message):
        return ML_DSA_65.sign(secret_key, message)

    def verify(public_key, message, signature):
        return ML_DSA_65.verify(public_key, message, signature)

    return "kyber-py + dilithium-py (pure-Python · NIST FIPS 203/204)", (
        kem_keypair, kem_encapsulate, kem_decapsulate, sig_keypair, sign, verify)


import os

# Set PRAHARI_PQC=pure to force the pure-Python provider (skips native liboqs).
_order = (_load_pure_python,) if os.environ.get("PRAHARI_PQC") == "pure" \
    else (_load_liboqs, _load_pure_python)

PROVIDER = None
_fns = None
for _loader in _order:
    try:
        PROVIDER, _fns = _loader()
        break
    except Exception:  # noqa: BLE001 — any failure just moves to the next provider
        continue

if _fns is None:
    raise RuntimeError(
        "No post-quantum provider available. Install the pure-Python fallback: "
        "pip install kyber-py dilithium-py")

kem_keypair, kem_encapsulate, kem_decapsulate, sig_keypair, sign, verify = _fns
