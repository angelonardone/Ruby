# Ruby: get_utility_keys - the DistributedCryptography wallet utility keys
from . import *

LABEL = 'ruby_utility_keys'.encode()
H = 0x80000000
# Relative to the BIP86 account m/86'/c'/0', in the order returned by Ruby
UTILITY_PATHS = [[H + 1000, H], [H + 2000, H], [H + 3000, H], [H + 4000, H], [H + 5000, H], [H + 6000]]


def _new_ephemeral_key():
    while True:
        try:
            privkey = os.urandom(32)
            wally.ec_private_key_verify(privkey)
            return privkey, wally.ec_public_key_from_private_key(privkey)
        except Exception:
            pass


def _expected_keys(network):
    """The keys computed locally with libwally from the default mnemonic, no passphrase"""
    is_main = network == 'mainnet'
    version = wally.BIP32_VER_MAIN_PRIVATE if is_main else wally.BIP32_VER_TEST_PRIVATE
    seed = wally.bip39_mnemonic_to_seed512(mnemonics.default, None)
    master = wally.bip32_key_from_seed(seed, version, 0)
    account = wally.bip32_key_from_parent_path(
        master, [H + 86, H + (0 if is_main else 1), H], wally.BIP32_FLAG_KEY_PRIVATE)
    return [wally.bip32_key_serialize(
                wally.bip32_key_from_parent_path(account, path, wally.BIP32_FLAG_KEY_PRIVATE),
                wally.BIP32_FLAG_KEY_PRIVATE)
            for path in UTILITY_PATHS]


@pytest.mark.parametrize('network', ['mainnet', 'testnet', 'localtest'])
def test_utility_keys(jade, network):
    privkey, pubkey = _new_ephemeral_key()
    rslt = jade.get_utility_keys(network, pubkey)
    assert len(rslt['pubkey']) == wally.EC_PUBLIC_KEY_LEN

    plaintext = wally.aes_cbc_with_ecdh_key(privkey, None, rslt['encrypted'], rslt['pubkey'],
                                            LABEL, wally.AES_FLAG_DECRYPT)
    assert len(plaintext) == len(UTILITY_PATHS) * wally.BIP32_SERIALIZED_LEN
    keys = [plaintext[i:i + wally.BIP32_SERIALIZED_LEN]
            for i in range(0, len(plaintext), wally.BIP32_SERIALIZED_LEN)]
    assert keys == _expected_keys(network)

    # Each a private key, and none of them is the account or a spending (non-hardened) key
    for key in keys:
        ext = wally.bip32_key_unserialize(key)
        assert wally.bip32_key_get_priv_key(ext) != bytes(32)
        assert wally.bip32_key_get_child_num(ext) & H


def test_utility_keys_bad_params(jade):
    _, pubkey = _new_ephemeral_key()
    for args, error in [
            ({'network': 'mainnet'}, 'valid pubkey'),
            ({'network': 'mainnet', 'pubkey': pubkey[:32]}, 'valid pubkey'),
            ({'network': 'mainnet', 'pubkey': bytes(33)}, 'valid pubkey'),
            ({'network': 'liquid', 'pubkey': pubkey}, 'valid network'),
            ({'pubkey': pubkey}, 'valid network')]:
        check_bad_params(jade.jade, ('badukeys', 'get_utility_keys', args), error)
