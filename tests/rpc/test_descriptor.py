from . import *
from .test_multisig import TEST_SEED_SINGLE_SIG

# A SLIP-77 (Liquid) blinding key - only used to check confidential descriptors are rejected
SLIP77_BLINDING_KEY = 'afacc503637e85da661ca1706c4ea147f1407868c48d8f92dd339ac272293cdc'


def test_descriptor_confidential_rejected(jade):
    """Ruby is Bitcoin only: confidential (Liquid ct()) descriptors are always rejected"""
    descriptor_no_slip77 = 'wsh(pkh(@0/<0;1>/*))'
    descriptor_with_slip77 = 'ct(slip77(@B),wpkh(@0/<0;1>/*))'
    signer = "[e3ebcc79/48'/1'/0'/2']tpubDDvj9CrVJ9kWXSL2kjtA8v53rZvTmL3HmWPvgD3hiTnD5KZuMkxSUsgGra\
Z9vavB5JSA3F9s5E4cXuCte5rvBs5N4DjfxYssQk1L82Bq4FE"
    blinding_key = SLIP77_BLINDING_KEY

    # Descriptor with SLIP-77 (confidential) should fail
    check_bad_params(
        jade.jade,
        ('btc_s77_bad', 'register_descriptor',
         {'network': 'testnet', 'descriptor_name': 'btcs77bad',
          'descriptor': descriptor_with_slip77,
          'datavalues': {'@B': blinding_key, '@0': signer}}),
        'Failed to parse descriptor')  # libwally is built without Elements: ct() is not recognised

    # Descriptor without SLIP-77 should pass.
    assert jade.register_descriptor(
      'testnet', 'btcnos77', descriptor_no_slip77, {'@0': signer}) is True


@with_test_cases('tests/rpc/data/descriptor/descriptor_*.json')
def test_miniscript_descriptor_registration(jade, test_case):
    """Test descriptor wallets"""
    _test_miniscript_descriptor_registration(jade, test_case)


@pytest.mark.mnemonic(mnemonics.singlesig_seed)
@with_test_cases('tests/rpc/data/descriptor/descriptor_ss_*.json')
def test_miniscript_descriptor_registration_ss(jade, mnemonic, test_case):
    """Test the descriptor wallets again, using a second signer"""
    _test_miniscript_descriptor_registration(jade, test_case)


def _test_miniscript_descriptor_registration(jade, test_case):
    # Register the descriptor
    inputdata = test_case['input']

    rslt = jade.register_descriptor(inputdata['network'],
                                    inputdata['descriptor_name'],
                                    inputdata['descriptor'],
                                    inputdata.get('datavalues'))
    assert rslt is True

    # Pull the data back, then reload (roundtrip) - should be a no-op
    roundtrip = jade.get_registered_descriptor(inputdata['descriptor_name'])
    assert roundtrip is not None
    assert roundtrip['descriptor'] == inputdata['descriptor']
    assert roundtrip.get('datavalues') == inputdata.get('datavalues')

    roundtrip['network'] = inputdata['network']  # the only item not roundtripped
    rslt = jade._jadeRpc('register_descriptor', roundtrip)  # push result structure back
    assert rslt

    # Check present and correct in 'get_registered_multisigs' also
    registered_descriptors = jade.get_registered_descriptors()
    descriptor_desc = registered_descriptors.get(inputdata['descriptor_name'])
    assert descriptor_desc is not None
    assert descriptor_desc['descriptor_len'] == len(inputdata['descriptor'])
    assert descriptor_desc['num_datavalues'] == len(inputdata.get('datavalues', []))

    # This includes 'get receive address' tests ...
    for addr_test in test_case['address_tests']:
        rslt = jade.get_receive_address(inputdata['network'],
                                        addr_test['branch'],
                                        addr_test['pointer'],
                                        descriptor_name=inputdata['descriptor_name'])
        assert rslt == addr_test['expected_address']

    # Check multisig equivalent if provided
    if 'multisig_equivalent' in inputdata:
        # Register the multisig equivalent
        descriptor = inputdata['multisig_equivalent']['descriptor']
        rslt = jade.register_multisig(inputdata['network'],
                                      inputdata['descriptor_name'],
                                      descriptor['variant'],
                                      descriptor['sorted'],
                                      descriptor['threshold'],
                                      descriptor['signers'])
        assert rslt is True

        # Check the receive addresses are the same
        for addr_test in test_case['address_tests']:
            paths = [[addr_test['branch'], addr_test['pointer']]] * len(descriptor['signers'])
            rslt = jade.get_receive_address(inputdata['network'],
                                            paths,
                                            multisig_name=inputdata['descriptor_name'])
            assert rslt == addr_test['expected_address']
