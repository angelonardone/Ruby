from . import *
from .. import _get_test_cases
from .test_sign_tx import _check_tx_signatures


TEST_SEED_SINGLE_SIG = 'b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c'


def _check_multisig_registration(jade, multisig_data):
    """Helper to check a multisig registration"""
    # Register the multisig
    inputdata = multisig_data['input']
    descriptor = inputdata['descriptor']
    rslt = jade.register_multisig(inputdata['network'],
                                  inputdata['multisig_name'],
                                  descriptor['variant'],
                                  descriptor['sorted'],
                                  descriptor['threshold'],
                                  descriptor['signers'])
    assert rslt is True

    # Pull the data back, then reload (roundtrip) - should be a no-op
    roundtrip = jade.get_registered_multisig(inputdata['multisig_name'])
    fetched = roundtrip['descriptor']
    assert fetched['variant'] == descriptor['variant']
    assert fetched['sorted'] == descriptor['sorted']
    assert fetched['threshold'] == descriptor['threshold']
    assert 'master_blinding_key' not in fetched  # Ruby: no Liquid blinding keys
    assert fetched['signers'] == descriptor['signers']

    roundtrip['network'] = inputdata['network']  # the only item not roundtripped

    rslt = jade._jadeRpc('register_multisig', roundtrip)  # push result structure back
    assert rslt

    # Check present and correct in 'get_registered_multisigs' also
    registered_multisigs = jade.get_registered_multisigs()
    multisig_desc = registered_multisigs.get(inputdata['multisig_name'])
    assert multisig_desc is not None
    assert multisig_desc['variant'] == descriptor['variant']
    assert multisig_desc['sorted'] == descriptor['sorted']
    assert multisig_desc['threshold'] == descriptor['threshold']
    assert multisig_desc['num_signers'] == len(descriptor['signers'])

    # This includes 'get receive address' tests ...
    for addr_test in multisig_data['address_tests']:
        rslt = jade.get_receive_address(inputdata['network'],
                                        addr_test['paths'],
                                        multisig_name=inputdata['multisig_name'])
        assert rslt == addr_test['expected_address']


@with_test_cases('tests/rpc/data/multisig/multisig_reg_*.json')
def test_generic_multisig_registration(jade, test_case):
    """Generic multisig - check register multisig wallets and get receive addresses"""
    # Run all of these tests since later test cases rely on them :(
    _check_multisig_registration(jade, test_case)

    # Ensure the 1of1 is registered at the end - same name will be used to overwrite
    # any large test cases (eg. nof15) that otherwise consume all the storage space.
    for multisig_data, _ in _get_test_cases('tests/rpc/data/multisig/multisig_reg_1of1.json'):
        inputdata = multisig_data['input']
        descriptor = inputdata['descriptor']
        rslt = jade.register_multisig(inputdata['network'],
                                      inputdata['multisig_name'],
                                      descriptor['variant'],
                                      descriptor['sorted'],
                                      descriptor['threshold'],
                                      descriptor['signers'])
        assert rslt


@with_test_cases('tests/rpc/data/multisig/multisig_file_*.json')
def test_generic_multisig_files(jade, test_case):
    """Check these multisig files load ok"""
    expected_result = test_case['expected_result']
    multisig_filename = test_case['input']['multisig_file']
    with open('tests/rpc/data/multisig/' + multisig_filename, 'r') as f:
        multisig_file = f.read()

    rslt = jade.register_multisig_file(multisig_file)
    assert rslt

    # Pull the data back, then reload (roundtrip) - should be a no-op
    roundtrip = jade.get_registered_multisig(expected_result['multisig_name'], as_file=True)
    rslt = jade.register_multisig_file(roundtrip['multisig_file'])
    assert rslt

    # Check registered as expected
    fetched = jade.get_registered_multisig(expected_result['multisig_name'])
    fetched = fetched['descriptor']
    assert fetched['variant'] == expected_result['variant']
    assert fetched['sorted'] == expected_result['sorted']
    assert fetched['threshold'] == expected_result['threshold']
    assert len(fetched['signers']) == expected_result['num_signers']

    registered_multisigs = jade.get_registered_multisigs()
    multisig_desc = registered_multisigs.get(expected_result['multisig_name'])
    assert multisig_desc is not None
    assert multisig_desc['sorted'] == expected_result['sorted']
    assert multisig_desc['variant'] == expected_result['variant']
    assert multisig_desc['threshold'] == expected_result['threshold']
    assert multisig_desc['num_signers'] == expected_result['num_signers']


@with_test_cases('tests/rpc/data/multisig/multisig_bad_file_*.json')
def test_generic_multisig_bad_files(jade, test_case):
    """Check these multisig files *do not* load"""
    expected_error = test_case['expected_error']
    multisig_filename = test_case['input']['multisig_file']
    with open('tests/rpc/data/multisig/' + multisig_filename, 'r') as f:
        multisig_file = f.read()

    try:
        jade.register_multisig_file(multisig_file)
        assert False, 'Expected error: ' + expected_error
    except JadeError as e:
        assert e.message == expected_error, 'Expected: ' + expected_error


@with_test_cases('tests/rpc/data/multisig/multisig_reg_*matches_ga_*.json')
def test_generic_multisig_matches_ga_addresses(jade, test_case):
    """
    This test checks that the generic multisig wallets 'matches_ga', do...
    ie. if I use the standard ga receive-address, I get the same result as
    that using 'generic multisig' (as the co-signers are set-up to match green)
    """
    inputdata = test_case['input']
    signers = inputdata['descriptor']['signers']

    # Register multisig wallet
    descriptor = inputdata['descriptor']
    rslt = jade.register_multisig(inputdata['network'],
                                  inputdata['multisig_name'],
                                  descriptor['variant'],
                                  descriptor['sorted'],
                                  descriptor['threshold'],
                                  descriptor['signers'])
    assert rslt is True

    # Check this test looks good - ie. 2of2 or 2of3
    assert inputdata['descriptor']['threshold'] == 2
    assert len(signers) == 2 or len(signers) == 3
    user_signer = signers[1]  # signers[0] is ga-service

    # Handle subaccounts
    if len(user_signer['derivation']) == 1:
        subaccount = 0
        branch = user_signer['derivation'][0]
    elif len(user_signer['derivation']) == 3:
        assert user_signer['derivation'][0] == 2147483651  # 3'
        assert user_signer['derivation'][1] > 2147483648  # subaccount'
        subaccount = user_signer['derivation'][1] - 2147483648  # unharden
        branch = user_signer['derivation'][2]
    else:
        assert False, 'Unexpected derivation for ga-multisig wallet'

    user_xpub = jade.get_xpub(inputdata['network'], user_signer['derivation'])
    assert user_xpub == user_signer['xpub']   # checks our xpub entry
    recovery_xpub = signers[2]['xpub'] if len(signers) == 3 else None

    # Check receive addresses fetched using normal green call matches the
    # expected results (which are tested as a generic multisig address above)
    for addr_test in test_case['address_tests']:
        ptr = addr_test['paths'][0][0]
        # check all signers have same single-entry path (ie. 'ptr')
        assert all(p == [ptr] for p in addr_test['paths'])
        rslt = jade.get_receive_address(inputdata['network'], subaccount, branch, ptr,
                                        recovery_xpub=recovery_xpub)
        assert rslt == addr_test['expected_address']


@with_test_cases('tests/rpc/data/multisig/multisig_reg_matches_ga_2of2.json')
def test_generic_multisig_matches_ga_signatures(jade, test_case):
    """Sign txns using generic multisig registration - should get same sigs as ga"""
    inputdata = test_case['input']
    descriptor = inputdata['descriptor']
    rslt = jade.register_multisig(inputdata['network'],
                                  inputdata['multisig_name'],
                                  descriptor['variant'],
                                  descriptor['sorted'],
                                  descriptor['threshold'],
                                  descriptor['signers'])
    assert rslt

    ga_2of2_multisig_name = inputdata['multisig_name']
    MULTISIG_SIGN_TXS = [
        'tests/rpc/data/multisig/txn_2of2_change.json',
        'tests/rpc/data/multisig/txn_segwit_multi_input.json']
    ga_2of2_multisig_txns = (list(_get_test_cases(testcase))[0][0]
                             for testcase in MULTISIG_SIGN_TXS)
    for ga_msig in ga_2of2_multisig_txns:
        inputdata = ga_msig['input']

        # Doctor the change paths to include the registered multisig name, but not
        # the multisig xpub root (ie. to only contain the final 'ptr' part)
        # (as the subact/branch is part of the multisig registration)
        for change in inputdata['change'] or []:
            if change is not None:
                path = change.pop('path')
                change['paths'] = [path[-1:]] * 2
                change['multisig_name'] = ga_2of2_multisig_name

        use_ae_signatures = inputdata.get('use_ae_signatures')
        use_legacy_flow = not use_ae_signatures and not get_jade_config().no_legacy_flow
        rslt = jade.sign_tx(inputdata['network'],
                            inputdata['txn'],
                            inputdata.get('inputs'),
                            inputdata['change'],
                            use_ae_signatures,
                            use_legacy_flow)

        # Check returned signatures
        _check_tx_signatures(jade, ga_msig, rslt)


@pytest.mark.mnemonic(mnemonics.singlesig_seed)
@with_test_cases('tests/rpc/data/multisig/multisig_reg_ss_*.json')
def test_generic_multisig_ss_signer(jade, mnemonic, test_case):
    """
    Register multisig wallets again - this checks that a second user from the multisig
    gets the same receive-address.  ie. in the tests 'multisig_reg_ss' the 'single sig'
    signer is also in the multisig, so we can check it from this signer also.
    """
    # set_seed() starts with clean_reset(), which removes all registrations.
    # Recreate this wallet under the main signer, then switch to the singlesig
    # signer without resetting so that we can exercise cross-wallet access.
    assert jade.set_mnemonic(mnemonics.default)
    _check_multisig_registration(jade, test_case)
    assert jade.set_seed(bytes.fromhex(TEST_SEED_SINGLE_SIG))

    # Test trying to access the multisig description registered under the
    # main test mnemonic fails (as must be registered by accessing wallet)
    inputdata = test_case['input']
    descriptor = inputdata['descriptor']
    try:
        for addr_test in test_case['address_tests']:
            rslt = jade.get_receive_address(inputdata['network'],
                                            addr_test['paths'],
                                            multisig_name=inputdata['multisig_name'])
            assert False, 'Accessing other wallet multisig should fail'
    except JadeError as e:
        assert e.code == JadeError.BAD_PARAMETERS
        assert e.message == 'Cannot de-serialise multisig wallet data', e.message

    # If we register the same multisig description to this wallet, it should produce
    # the same addresses as it did previously (for the other signatory)
    _check_multisig_registration(jade, test_case)
    pass


def test_register_multisig_too_many_signers(jade):
    """More signers than MAX_ALLOWED_SIGNERS must be rejected."""
    try:
        MAX_ALLOWED_SIGNERS = 15
        signers = [{}] * (MAX_ALLOWED_SIGNERS + 1)
        jade.register_multisig('testnet', 'msig_toomany', 'sh(multi(k))', False, 1, signers)
        assert False, 'Expected error for oversized signers array'
    except JadeError as e:
        assert e.code == JadeError.BAD_PARAMETERS, e
        assert e.message == 'Failed to extract valid co-signers from parameters', e.message
