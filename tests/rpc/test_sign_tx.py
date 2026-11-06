from . import *
import sys


def _get_signing_data(test_case, tx):
    """Helper to fetch the scriptpubkeys and input values for sign_tx tests"""
    test_input = test_case['input']

    inputs = test_input['inputs']
    scriptpubkeys = wally.map_init(len(inputs), None)
    values = wally.map_init(len(inputs), None)
    for i, inputdata in enumerate(inputs):
        if not inputdata:
            pass  # No-op
        elif inputdata.get('input_tx'):
            # Fetch info from the prevout for the input
            utxo_index = wally.tx_get_input_index(tx, i)
            utxo = wally.tx_from_bytes(inputdata['input_tx'], 0)
            wally.map_add_integer(scriptpubkeys, i,
                                  wally.tx_get_output_script(utxo, utxo_index))
            # Satoshi value (as uint64 native-endian bytes)
            value = wally.tx_get_output_satoshi(utxo, utxo_index)
            wally.map_add_integer(values, i, value.to_bytes(8, byteorder=sys.byteorder))
        else:
            # If no input_tx, sats can be passed instead (Deprecated).
            # Only valid for non-taproot, single-input segwit txns
            assert inputdata['is_witness']
            assert len(inputs) == 1
            # Satoshi value (as uint64 native-endian bytes)
            value = inputdata['satoshi']
            wally.map_add_integer(values, i, value.to_bytes(8, byteorder=sys.byteorder))
    return scriptpubkeys, values


def _check_tx_signatures(jade, test_case, rslt):
    """
    Helper to verify tx signatures - handles checking an Anti-Exfil signature
    contains the entropy that was passed in by the host.
    """
    assert len(rslt) == len(test_case['expected_output'])

    # Get tx-level details
    test_input = test_case['input']
    network = test_input['network']
    use_ae_signatures = test_input.get('use_ae_signatures', False)

    tx = wally.tx_from_bytes(test_input['txn'], 0)

    scriptpubkeys, values = _get_signing_data(test_case, tx)
    cache = wally.map_init(16, None)  # TODO: Use a wally constant when available

    # Iterate over the results verifying each signature
    for i, (expected, actual) in enumerate(zip(test_case['expected_output'], rslt)):
        # NOTE: signatures returned have the sighash byte appended
        if use_ae_signatures:
            # Anti-Exfil signer_commitment and signature
            # (might not be low-r, but should be low-s)
            assert tuple(expected) == actual

            # Check sig length is low-s (ie. remove one from the possible max length)
            # Then add one byte back for the sighash byte.
            assert len(actual[1]) <= wally.EC_SIGNATURE_DER_MAX_LEN + 1 - 1
            signer_commitment, signature = actual
        else:
            # Standard EC signature should be low-s and low-r
            assert actual == expected

            # NOTE: low-s is implied/assumed here, so no need to remove one from max-len
            assert len(actual) <= wally.EC_SIGNATURE_DER_MAX_LOW_R_LEN + 1
            signer_commitment, signature = None, actual  # No signer_commitment for EC sig

        if not len(signature):
            continue  # We didn't sign this input, ignore it

        # We signed this input, get the signature message hash (ie. the
        # hash value that was signed) and verify the signature against it
        inputdata = test_input['inputs'][i]
        script = inputdata['script']
        is_p2tr = script[0] == 0x51 and script[1] == 32  # OP_1 [32 byte xonly pubkey]
        def_sighash = wally.WALLY_SIGHASH_DEFAULT if is_p2tr else wally.WALLY_SIGHASH_ALL
        sighash = inputdata.get('sighash', def_sighash)
        if is_p2tr:
            sighash_type = wally.WALLY_SIGTYPE_SW_V1
            script = None  # Taproot uses the script in 'scriptpubkeys'
        elif inputdata['is_witness']:
            sighash_type = wally.WALLY_SIGTYPE_SW_V0
        else:
            sighash_type = wally.WALLY_SIGTYPE_PRE_SW

        key_version, codesep_pos, annex, genesis = 0, wally.WALLY_NO_CODESEPARATOR, None, None
        msghash = wally.tx_get_input_signature_hash(
            tx, i, scriptpubkeys, None, values, script, key_version,
            codesep_pos, annex, genesis, sighash, sighash_type, cache)

        # Check sighash and verify signature!
        if is_p2tr:
            # Either 64 byte default sig or 65 byte non-default with sighash byte appended
            if len(signature) == wally.EC_SIGNATURE_LEN:
                assert sighash == wally.WALLY_SIGHASH_DEFAULT
            else:
                assert len(signature) == wally.EC_SIGNATURE_LEN + 1
                assert sighash != wally.WALLY_SIGHASH_DEFAULT
                assert signature[-1] == sighash
            rawsig = signature[:wally.EC_SIGNATURE_LEN]  # Ignore any sighash byte
        else:
            # A DER encoded sig with sighash byte appended
            assert signature[-1] == sighash
            rawsig = wally.ec_sig_from_der(signature[:-1])  # truncate sighash byte

        host_entropy = inputdata.get('ae_host_entropy') if use_ae_signatures else None
        verify_signature(jade, network, msghash, inputdata['path'],
                         host_entropy, signer_commitment, rawsig, is_schnorr=is_p2tr)


def _test_sign_tx_case(jade, test_case):
    inputdata = test_case['input']
    expected_output = test_case.get('expected_output')
    expected_error = test_case.get('expected_error')
    assert expected_output or expected_error
    use_ae_signatures = inputdata.get('use_ae_signatures')
    use_legacy_flow = not use_ae_signatures and not get_jade_config().no_legacy_flow
    try:
        rslt = jade.sign_tx(inputdata['network'],
                            inputdata['txn'],
                            inputdata['inputs'],
                            inputdata['change'],
                            use_ae_signatures,
                            use_legacy_flow)
        assert not expected_error, f"Expected an error in {test_case['filename']}"
        # Check returned signatures
        _check_tx_signatures(jade, test_case, rslt)
    except JadeError as err:
        assert expected_error, f"Unexpected error {err.message} in {test_case['filename']}"
        assert err.message == expected_error, \
            f"Wrong error '{err.message}' in {test_case['filename']}"

        if use_legacy_flow:
            # Only the legacy flow returns extra responses
            for i in range(test_case.get('extra_responses', 0)):
                logger.debug(jade.jade.read_response())


def _test_sign_tx(jade, test_case):
    # Run the signing test case
    _test_sign_tx_case(jade, test_case)

    if 'expected_legacy_output' in test_case and 'expected_error' not in test_case:
        # Test case has non-Anti-exfil signing results, test them also.
        test_case['input']['use_ae_signatures'] = False
        for txinput in test_case['input']['inputs']:
            for k in ['ae_host_commitment', 'ae_host_entropy']:
                txinput[k] = bytes()
        test_case['expected_output'] = test_case['expected_legacy_output']
        _test_sign_tx_case(jade, test_case)


# Multisig
@with_test_cases('tests/rpc/data/sign_tx/tx_*.json')
def test_sign_tx(jade, test_case):
    _test_sign_tx(jade, test_case)


@with_test_cases('tests/rpc/data/sign_tx/bad_tx_*.json')
def test_sign_tx_bad(jade, test_case):
    _test_sign_tx(jade, test_case)


# Singlesig
@pytest.mark.mnemonic(mnemonics.singlesig)
@with_test_cases('tests/rpc/data/sign_tx/ss_tx_*.json')
def test_sign_tx_singlesig(jade, mnemonic, test_case):
    _test_sign_tx(jade, test_case)


@pytest.mark.mnemonic(mnemonics.singlesig)
@with_test_cases('tests/rpc/data/sign_tx/bad_ss_tx_*.json')
def test_sign_tx_bad_singlesig(jade, mnemonic, test_case):
    _test_sign_tx(jade, test_case)


def _varint(n):
    """Encode an integer as a Bitcoin compact-size (varint) integer."""
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def _make_tx_bytes(num_inputs, num_outputs):
    """Build a minimal raw Bitcoin transaction (version 2, no witness) with the
    given number of inputs/outputs, to exercise the tx input/output caps."""
    tx = (2).to_bytes(4, 'little')  # version
    tx += _varint(num_inputs)  # input count
    for _ in range(num_inputs):
        tx += bytes(32)  # prevout txid
        tx += (0).to_bytes(4, 'little')  # prevout index
        tx += b'\x00'  # empty script
        tx += (0xffffffff).to_bytes(4, 'little')  # sequence
    tx += _varint(num_outputs)  # output count
    for _ in range(num_outputs):
        tx += (1000).to_bytes(8, 'little')  # value
        tx += b'\x01' + b'\x51'  # script: OP_TRUE
    tx += (0).to_bytes(4, 'little')  # locktime
    return tx


def test_sign_tx_too_many_inputs(jade):
    """A tx with more than MAX_TX_INPUTS inputs must be rejected."""
    MAX_TX_INPUTS = 256
    txn = _make_tx_bytes(257, 1)
    try:
        txinputs = [None] * (MAX_TX_INPUTS + 1)
        jade.sign_tx('testnet', txn, txinputs, None, use_ae_signatures=False, use_legacy=False)
        assert False, 'Expected error for oversized tx input count'
    except JadeError as e:
        assert e.code == JadeError.BAD_PARAMETERS, e
        assert e.message == 'Too many transaction inputs', e.message


def test_sign_tx_too_many_outputs(jade):
    """A tx with more than MAX_TX_OUTPUTS outputs must be rejected."""
    MAX_TX_OUTPUTS = 64
    txn = _make_tx_bytes(1, MAX_TX_OUTPUTS + 1)
    try:
        jade.sign_tx('testnet', txn, [None], None, use_ae_signatures=False, use_legacy=False)
        assert False, 'Expected error for oversized tx output count'
    except JadeError as e:
        assert e.code == JadeError.BAD_PARAMETERS, e
        assert e.message == 'Too many transaction outputs', e.message


def test_sign_tx_no_outputs(jade):
    """A tx with no outputs must be rejected"""
    txn = _make_tx_bytes(1, 0)
    try:
        jade.sign_tx('testnet', txn, [None], None, use_ae_signatures=False, use_legacy=False)
        assert False, 'Expected error for tx with no outputs'
    except JadeError as e:
        assert e.code == JadeError.BAD_PARAMETERS, e
        assert e.message == 'Transaction has no inputs or outputs', e.message
