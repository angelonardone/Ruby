from . import *
from .test_multisig import TEST_SEED_SINGLE_SIG


@with_test_cases('tests/rpc/data/address/greenaddress.json')
def test_get_greenaddress_receive_address(jade, test_case):
    for network, subact, branch, ptr, recovxpub, csvblocks, expected in test_case:
        rslt = jade.get_receive_address(network, subact, branch, ptr, recovery_xpub=recovxpub,
                                        csv_blocks=csvblocks)
        assert rslt == expected


@pytest.mark.mnemonic(mnemonics.singlesig_seed)
@with_test_cases('tests/rpc/data/address/single_sig_addr.json')
def test_get_singlesig_receive_address(jade, mnemonic, test_case):
    for network, variant, path, expected in test_case:
        rslt = jade.get_receive_address(network, path, variant=variant)
        assert rslt == expected


@with_test_cases('tests/rpc/data/address/xpub.json')
def test_get_xpubs(jade, test_case):
    # NOTE: for get-xpub the root (empty path array) can be accessed (to allow
    # external creation of watch-only public key tree)
    # NOTE: network 'mainnet' results in 'xpub' prefix, else 'tpub'
    for path, network, expected in test_case:
        rslt = jade.get_xpub(network, path)
        assert rslt == expected
