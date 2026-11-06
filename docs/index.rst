.. Jade documentation master file, created by
   sphinx-quickstart on Tue May 12 13:33:32 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Jade's RPC documentation!
====================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

* All Jade RPC messages are CBOR, roughly based on the format of json-rpc messges.
* The order of named fields inside the messages is unimportant.  The order of items in array elements usually is important.
* In most cases the flow is message-reply-message-reply... the exception is the legacy sign-tx flow where n messages are sent before n replies are received.
* In some cases there may be a delay between sending a message and a reply being sent, where some physical interaction with the Jade unit is required.
* In general, the types used are string, boolean, uint32/64, and raw byte-strings for binary data.
* Every message contains an `id` field - an arbitrary string up to 16 characters - which is included in the reply.
* Several calls require a `network` parameter.  Allowed values are: 'mainnet'. If using a test wallet, 'testnet' and 'localtest' are allowed.  (Ruby is Bitcoin only: the Liquid networks of upstream Jade are not supported.)
* Successful action replies include a `result` structure, specific to each method.
* Failed/errored/declined actions instead include a common `error` structure.

.. _common_error_reply:

common error reply
------------------

.. code-block:: cbor

    {
        "id": "5",
        "error": {
            "code": -32603,
            "message": "There was an error with your request"
            "data": <bytes>
        }
    }

* 'code' values are listed in `main/utils/cbor_rpc.h`.
* 'message' should be a meaningful string describing the error encountered.
* 'data' content is optional, and usually unused/null.

.. _get_extended_data_request:

get_extended_data request
-------------------------

.. code-block:: cbor

    {
        "id": "11",
        "method": "get_extended_data"
        "params": {
            "origid": "1234",
            "orig": "sign_psbt",
            "seqnum": 3,
            "seqlen": 6
        }
    }

* 'get_extended_data' is to be used where a prior reply has included 'seqnum' and 'seqlen' fields which indicate incomplete data
* 'origid' should be the id of the original request message and initial reply
* 'orig' should be the 'method' of the original request message
* 'seqlen' should be the 'seqlen' in the replies - indicating the total number of message replies which will be required
* 'seqnum' should indicate the next fragment required - it should always be less-than or equal-to the 'seqlen'
* NOTE: atm 'seqnum' *MUST* indicate the next fragment.  ie. ie must be the last received seqnum + 1.
* NOTE: at the moment these messages are only used for 'sign_psbt' replies, where the full psbt binary may be sufficiently large that it needs to be split over multiple messages.  See sign_psbt_request_.
* Use of these messages may increase in future firmware releases.

.. _get_extended_data_reply:

get_extended_data reply
-----------------------

.. code-block:: cbor

    {
        "id": "11",
        "result": {
            <as appropriate for parent message>
        }
    }

* The content of the message will be dependent on the original message whose reply data is being split over multiple messages.

.. _ping_request:

ping request
------------

Used to test the connection to Jade and that Jade is powered on and receiving data, which returns whether the main task is currently handling a client message, handling user ui menu navigation, or is idle.

NOTE: unlike all other calls this is not queued and handled in fifo order - this message is handled immediately and the response sent as quickly as possible.
This call does not block.
If this call is made in parallel with Jade processing other messages, the replies may be out of order (although the message 'id' should still be correct).
Use with caution.

.. code-block:: cbor

    {
        "id": "2712",
        "method": "ping"
    }

.. _ping_reply:

ping reply
----------

.. code-block:: cbor

    {
        "id": "2712",
        "result": 0
    }

* The result is 0 if the main jade task is idle, 1 if handling a client message, or 2 if handling ui menu navigation.
* If used with a short timeout this message is ideal for detecting whether Jade is powered/active.

.. _get_version_info_request:

get_version_info request
------------------------

Used to obtain summary fields describing this Jade hw unit.

.. code-block:: cbor

    {
        "id": "90210",
        "method": "get_version_info"
    }

.. _get_version_info_reply:

get_version_info reply
----------------------

.. code-block:: cbor

    {
        "id": "90210",
        "result": {
            "JADE_VERSION": "0.1.32",
            "JADE_OTA_MAX_CHUNK": 4096,
            "JADE_CONFIG": "BLE",
            "BOARD_TYPE": "JADE",
            "JADE_FEATURES": "SB",
            "IDF_VERSION": "v4.3.1",
            "CHIP_FEATURES": "32000000",
            "EFUSEMAC": "246F288F6364",
            "BATTERY_STATUS": 5,
            "JADE_STATE": "LOCKED",
            "JADE_INTERFACE": "NONE",
            "JADE_NETWORKS': "MAIN",
            "JADE_HAS_PIN": true
        }
    }

* 'BATTERY_STATUS' : positive integer value up to 5 (fully charged).

* 'JADE_STATE' :

  - 'UNINIT' - no wallet set on the hw, mnemonic not entered, unit uninitialised.
  - 'UNSAVED' - wallet mnemonic has been set on hw, but not yet persisted with blind pinserver.
  - 'LOCKED' - wallet set, but currently locked - requires PIN entry to unlock.
  - 'READY' - wallet set and unlocked for this interface, ready to use.
  - 'TEMP' - hw currently set with a temporary ('Emergency Restore') wallet, ready to use.

* 'JADE_INTERFACE' : the connection interface which currently holds the unlocked wallet, if any.
  While a wallet is held by one interface it cannot be used over another

  - 'NONE' - wallet is not currently held by any connection interface (so can be unlocked)
  - 'QR' - wallet is held by the on-device QR interface (eg. a temporary 'QR Mode' wallet)
  - 'SERIAL' - wallet is held by the USB/serial connection
  - 'BLE' - wallet is held by the Bluetooth connection

* 'JADE_NETWORKS' :

  - 'MAIN' - wallet is locked to mainnet/production networks and cannot be used on testnet or regtest networks.
  - 'TEST' - wallet is locked to testnet/regtest/localtest networks, and cannot be used on mainnet.
  - 'ALL' - wallet is not (yet) locked to a specific network type.

.. _sign_attestation_request:

sign_attestation request
------------------------

Request to sign to confirm hw unit authenticity using a hw-embedded RSA-4096 key.

NOTE: this call is only supported by ESP32S3-based hw units.

.. code-block:: cbor

    {
        "id": "84",
        "method": "sign_attestation",
        "params": {
            "challenge": <bytes>
        }
    }

* NOTE: 'challenge' will be hashed with SHA256 and padded according to PKCS1v1.5 before being signed.

.. _sign_attestation_reply:

sign_attestation reply
----------------------

* NOTE: The reply is not sent until the user has explicitly confirmed signing on the hw.

.. code-block:: cbor

    {
        "id": "84",
        "result": {
            "signature": <512 bytes>
            "pubkey_pem": <pem string>
            "ext_signature": <bytes>
        }
    }

* 'signature' is the RSA signature of the hw-embedded RSA-4096 key over the hashed and padded challenge bytes.
* 'pubkey_pem' is the exported PEM of the pubkey of the hw-embedded RSA key used to sign the challenge.  Base64 bytes with a trailing nul-terminator.
* 'ext_signature' is an RSA signature of the verifying authority over the pubkey_pem bytes (including nul-terminator).
* NOTE: the caller should have the RSA pubkey of the verifying authority in order to verify ext_signature and hence the authenticity of the hw unit.

.. _update_pinserver_request:

update_pinserver request
------------------------

Call to update the details of the blind pinserver used to authenticate Jade unlock attempts.

.. code-block:: cbor

    {
        "id": "101",
        "method": "update_pinserver"
        "params": {
            "reset_details": true,
            "reset_certificate": true,
            "urlA": "https://test.pinserver.com",
            "urlB": "http://pinserveronion.com",
            "pubkey": <33 bytes>,
            "certificate": "<certificate pem string>"
        }
    }

* All fields are optional (although an empty message has no effect).
* 'reset_details' - resets to default pinserver (ie. *https://j8d.io*)
* 'reset_certificate' - resets any additional certificate (to none)
* 'urlA'/'urlB' - sets up to two urls for the pinserver.  (Setting only urlA will set urlB to none).
* 'pubkey' - 33-byte EC public key of pinserver.

- Note: Jade applies some validation to parameter combinations, for example it is not possible to set only 'urlB', to set 'pubkey' without at least 'urlA', to both 'set' and 'reset' fields, etc.

.. _update_pinserver_reply:

update_pinserver reply
----------------------

.. code-block:: cbor

    {
        "id": "101",
        "result": true
    }

.. _set_epoch_request:

set_epoch request
-----------------

Jade has an internal clock/oscillator, but no absolute time is retained over power-cycles.
This call allows setting the current epoch time, to initialise the internal clock.
NOTE: this is required to use the TOTP authentication feature.

.. code-block:: cbor

    {
        "id": "926",
        "method": "set_epoch"
        "params": {
            "epoch": 1654086434
        }
    }

* 'epoch' - unix epoch time, in seconds.

.. _set_epoch_reply:

set_epoch reply
---------------

.. code-block:: cbor

    {
        "id": "926",
        "result": true
    }

.. _add_entropy_request:

add_entropy request
-------------------

Jade has an internal entropy pool generated by sampling several of the environmental sensors,
but this call allows the client to contribute to that entropy pool by passing in additional
entropy bytes.

.. code-block:: cbor

    {
        "id": "925",
        "method": "add_entropy"
        "params": {
            "entropy": <bytes>
        }
    }

* 'entropy' - a byte sequence of any length is accepted, and added into the entropy pool.

.. _add_entropy_reply:

add_entropy reply
-----------------

.. code-block:: cbor

    {
        "id": "925",
        "result": true
    }

.. _logout_request:

logout request
--------------

Logout of any wallet loaded on Jade.  Key material is freed and zero'd.
Jade is returned to a 'locked' state, with no keys/wallet loaded.

.. code-block:: cbor

    {
        "id": "14159",
        "method": "logout"
    }

.. _logout_reply:

logout reply
------------

.. code-block:: cbor

    {
        "id": "14159",
        "result": true
    }

.. _auth_user_request:

auth_user request
-----------------

A call to 'auth_user' is required to unlock a Jade wallet and also to complete wallet initialisation.

.. code-block:: cbor

    {
        "id": "6",
        "method": "auth_user",
        "params": {
            "network": "mainnet"
            "epoch": 1654086434
        }
    }

* If completing initialisation, the call will result in the user setting a PIN (on the device) to persist the wallet with the blind pinserver. The wallet is locked to the type of network passed (ie. locked for use on mainnet, OR for use on testnet/regtest networks).
* If unlocking an initialised unit, the network passed indicates the intended network to use - an error is returned if this is inconsistent with that set when the wallet was initialised/persisted. The user will be asked to enter the PIN on the device, and the blind pinserver will be used to unlock the wallet.
* 'epoch' is optional, and if passed sets the value of the internal clock - see set_epoch_request_ above.
* Calling 'auth_user' on a wallet that is already unlocked validates the passed network and sets any epoch value, and returns immediately without requiring user interation.

.. _auth_user_reply:

auth_user reply
---------------

.. code-block:: cbor

    {
        "id": "6",
        "result": true
    }

In this case the Jade is already/successfully logged in and the passed network is consistent with the wallet.
Continue ahead with OTA, get-xpub, get-address or signing messages and transactions.

Otherwise if a message like the below is received, the given http end point must be called (POST) to authenticate the user, passing the 'data' payload to the remote blind pinserver, and passing the reply into the Jade method given.

NOTE: in this instance some of 'byte' data fields may actually be hexidecimal strings - this data is opaque to the client and should simply be passed between Jade and the blind pinserver.


auth_user reply
---------------

.. code-block:: cbor

    {
        "id": "R2D2",
        "result": {
            "http_request": {
                "params": {
                    "urls": [
                        "url": "https://jadepin.blockstream.com/get_pin",
                        "onion": "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion/get_pin"
                    ],
                    "method": "POST",
                    "accept": "json",
                    "data": {
                        "data": "\"%*>PH1h<i>iAOAG4;fO)Ro/552Gt+2\":s*g2Cr`70`em!1p.oQTHFTkeDa%J2p?%k-)kG=[5>f(8&IV=X-2;Bc6-PIG$=\\2X/;odu0Ab-=B(6[K88p68<u.iin(YSGge#S0=5d%EMN6NohJ=0O[J6Og+G1cD\\PQ9$Ul!Xk]1.d9fs*16an:o>J!d0Z%].Q)m\";\\*>b6q%HOB[NU5bpZ\\Bil\\b+Gh!dl<5-0>h!@gW3ZV=ZP6i^$iIf"
                    }
                }
                "on-reply": "pin"
            }
        }
    }

The 'data' should be sent (as json) to the url provided (either is fine), and the response body forwarded to the 'pin' Jade method.
The request should look like the below:

.. _pin_request:

pin request
-----------

.. code-block:: cbor

    {
        "id": "C3PO",
        "method": "pin",
        "params": {
            "data": "kbt_._7o&sa2TOJU$lj.J<@oh)a?l>-CReEF5nY3HP9CdeSjEA8PCU'Hj?#e-mhV3@KE:DZhGNJL\"#L\\ObZ:s-s0R6nk':WB!WY@.\"ja($)o37B*9iHqsL4t"
        }
    }

.. _pin_reply:

pin reply
---------

.. code-block:: cbor

    {
        "id": "C3PO",
        "result": true
    }

* A result of 'true' means the PIN was correct and the Jade wallet is now unlocked and ready to use.
* A result of 'false' here would imply the entered PIN was incorrect, authentication failed, and so the wallet is still locked.

.. _ota_request:

ota request
-----------

Request to initiate a firmware update passing the full firmware image.

.. code-block:: cbor

    {
        "id": "13",
        "method": "ota",
        "params": {
            "fwsize": 926448,
            "cmpsize": 579204,
            "cmphash": <32 bytes>,
            "fwhash": <32 bytes>,
            "extended_replies": false
        }
    }

* 'fwsize' is the total length of the final firmware when uncompressed.
* 'cmpsize' is the length of the compressed firmware image which will be uploaded.
* 'cmphash' is the sha256 hash of the compressed firmware image.
* 'fwhash' is the sha256 hash of the final firmware image to be booted.
* 'extended_replies' is optional, and if set enables rich progress replies (see ota_data_reply_).
* NOTE: 'fwhash' is a new addition and is optional at this time, although it will become mandatory in a future release.

.. _ota_reply:

ota reply
---------

.. code-block:: cbor

    {
        "id": "13",
        "result": true
    }


After this reply is received, the compressed firmware is sent in chunks using 'ota_data' messages.  The chunks can be any size up to the `JADE_OTA_MAX_CHUNK` limit (see get_version_info_request_).

.. _ota_delta_request:

ota_delta request
-----------------

Request to initiate a firmware update using a binary diff/patch to be applied onto the current running firmware.

.. code-block:: cbor

    {
        "id": "7",
        "method": "ota_delta",
        "params": {
            "fwsize": 926448,
            "patchsize": 987291,
            "cmpsize": 14006,
            "cmphash": <32 bytes>,
            "extended_replies": false
        }
    }

* 'fwsize' is the total length of the final firmware when uncompressed.
* 'patchsize' is the length of the patch when uncompressed.
* 'cmpsize' is the length of the compressed firmware patch which will be uploaded.
* 'cmphash' is the sha256 hash of the compressed firmware patch.
* 'extended_replies' is optional, and if set enables rich progress replies (see ota_data_reply_).

.. _ota_delta_reply:

ota delta reply
---------------

See ota_reply_

.. _ota_data_request:

ota_data request
----------------

.. code-block:: cbor

    {
        "id": "48",
        "method": "ota_data",
        "params": <bytes>
    }

.. _ota_data_reply:

ota_data reply
--------------

.. code-block:: cbor

    {
        "id": "48",
        "result": true
    }

or, if 'extended_replies' was set in the original request, and the Jade fw supports this:

.. code-block:: cbor

    {
        "id": "48",
        "result": {
            "confirmed": true
            "progress": 58
        }
    }

* 'confirmed' is initially false, until the user verifies the OTA upload, then all subsequent replies will be true
* 'progress' is the percentage complete value as shown on Jade (which is based on uncompressed final firmware written, so can differ from the proportion of compressed data uploaded)

NOTE: 'extended_replies' is supported as of Jade fw 1.0.33

We then send the 'ota_complete' message to verify the OTA was successful (before the device reboots).

.. _ota_complete_request:

ota_complete request
--------------------

.. code-block:: cbor

    {
        "id": "50",
        "method": "ota_complete"
    }

.. _ota_complete_reply:

ota_complete reply
------------------

.. code-block:: cbor

    {
        "id": "50",
        "result": true
    }

* A 'true' response implies the firmware upload completed successfully, and the next restart (which should happen immediately/automatically) will attempt to boot the new firmware.


.. _register_descriptor_request:

register_descriptor request
---------------------------

Jade can store up to 16 user-defined miniscript descriptor wallet configurations, which need to be confirmed on the hw.

.. code-block:: cbor

    {
        "id": "186282",
        "method": "register_descriptor"
        "params": {
            "network": "mainnet",
            "descriptor_name": "inheritance",
            "descriptor": "wsh(or_d(pk(@0/<0;1>/*),and_v(v:multi(2,@1/<0;1>/*,@2/<0;1>/*),older(4320))))",
            "datavalues": {
                {
                    "key": "@0",
                    "value": "[1bf12fe0/48'/1'/0'/2']tpubDEHXLZfMAAM5duEnX6SSnZjGYbrxqXvRJmMxw8MFwr3gu4LC4DSxR9KVEfVDVcZxre4XL5tGcwVRrHwQ9euTMnSq6P6BqREemaqrFsC96Fy",
                },
                {
                    "key": "@1",
                    "value": "[eda3d606/48'/1'/0'/2']tpubDEAmqvQkhqP6SbfbSPu3AeRR9kfHLFXYvNDiWashLy7V2zicg1YLg654AqfomsC6kFwTs4MpcnqwxN2AnYAqi5JZeuVDBn3rfZZLTaAuS8Y",
                },
                {
                    "key": "@2",
                    "value": "[e1640396/48'/1'/0'/2']tpubDFgDvZifofePphQiVjLfkov8YTDg3UPuHRvt6LzbySYMZQhN19p6zvR7NTEXi1ZJAMNostHMTnz2sfXXYcJFQqtyCnNuUfgYqsahxTLGJq2",
                }
            }
        }
    }

* 'descriptor_name' is a string, and must be less than 16 characters long.  Using an existing name will overwrite the corresponding descriptor registration record.
* 'descriptor' is the descriptor string.  It must be a BIP 388 'wallet policy' miniscript expression with the keys presented in the accompanying datavalues map.
* 'datavalues' is the map of signers' keys, which must include an entry for the Jade signer.


.. _register_descriptor_reply:

register_descriptor reply
-------------------------

.. code-block:: cbor

    {
        "id": "186282",
        "result": true
    }

.. _get_registered_descriptors_request:

get_registered_descriptors request
----------------------------------

Call to fetch brief summary of any registered descriptor wallets associated with the hw signer.

.. code-block:: cbor

    {
        "id": "82",
        "method": "get_registered_descriptors"
    }

.. _get_registered_descriptors_reply:

get_registered_descriptors reply
--------------------------------

.. code-block:: cbor

    {
        "id": "82",
        "result": {
            "work-team": {
                "descriptor_len": 79
                "num_datavalues": 2
            },
            "family": {
                "descriptor_len": 132
                "num_datavalues": 3
            }
        }
    }

.. _get_registered_descriptor_request:

get_registered_descriptor request
---------------------------------

Call to fetch details of any registered descriptor wallets associated with the hw signer.

.. code-block:: cbor

    {
        "id": "87",
        "method": "get_registered_descriptor"
        "params": {
            "descriptor_name": "2of2decay"
        }
    }

.. _get_registered_descriptor_reply:

get_registered_descriptor reply
-------------------------------

.. code-block:: cbor

    {
        "id": "87",
        "descriptor_name": "2of2decay",
        "descriptor": "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:pkh(@0/<2;3>/*),older(65535))))",
        "datavalues": {
            "@0": "[1273da33/48'/1'/0'/2']tpubDEAjmvwVDj4aTdNLyLdoVGdEuRf8ZMsZEun6Aa2uMHa3DFNSzXQFt8DY62gi37RuaPTcpoNFage2h6dPHABssCnWcp2j6srQTpWbGEKHgU1",
            "@1": "[e3ebcc79/48'/1'/0'/2']tpubDDvj9CrVJ9kWXSL2kjtA8v53rZvTmL3HmWPvgD3hiTnD5KZuMkxSUsgGraZ9vavB5JSA3F9s5E4cXuCte5rvBs5N4DjfxYssQk1L82Bq4FE"
        }
    }

.. _register_multisig_request:

register_multisig request
-------------------------

Jade can store up to 16 user-defined multisig wallet configurations, which need to be confirmed on the hw.

.. code-block:: cbor

    {
        "id": "6000000$",
        "method": "register_multisig"
        "params": {
            "network": "mainnet",
            "multisig_name": "small_beans",
            "descriptor": {
                "variant": "sh(multi(k))",
                "sorted": true,
                "threshold": 2,
                "signers": [
                    {
                        "fingerprint": <4 bytes>,
                        "derivation": [44, 2147483648, 2147483648],
                        "xpub": "tpubDDCNstnPhbdd4vwbw5UWK3vRQSF1WXQkvBHpNXpKJAkwFYjwu735EH3GVf53qwbWimzewDUv68MUmRDgYtQ1AU8FRCPkazfuaBp7LaEaohG",
                        "path": [3, 1]
                    },
                    {
                        "fingerprint": <4 bytes>,
                        "derivation": [2147483651, 2147483649, 1],
                        "xpub": "tpubDDExQpZg2tziZ7ACSBCYsY3rYxAZtTRBgWwioRLYqgNBguH6rMHN1D8epTxUQUB5kM5nxkEtr2SNic6PJLPubcGMR6S2fmDZTzL9dHpU7ka",
                        "path": [1]
                    }
                ]
            }
        }
    }

or:

.. code-block:: cbor

    {
        "id": "6000000$",
        "method": "register_multisig"
        "params": {
            "multisig_file": "Name: MainWallet\nPolicy: 2 of 3\nFormat: P2WSH\nDerivation: m/48'/0'/0'/2\n\nB237FE9D: xpub6E8C7BX4c7qfTsX7urnXggcAyFuhDmYLQhwRwZGLD9maUGWPinuc9k96ejhEQ1DCk..."
        }
    }

* 'multisig_name' is a string, and must be less than 16 characters long.  Using an existing name will overwrite the corresponding multisig registration record.
* 'variant' indicates the script type used, and must be one of: 'sh(multi(k))', 'wsh(multi(k))' or 'sh(wsh(multi(k)))'
* 'fingerprint' is the 4-byte wallet origin fingerprint - at least one signer must reference the Jade signer's root xpub fingerprint.
* 'derivation' is the path from the origin to the given xpub - currently it is only used for the Jade signer, where it is used to verify the passed xpub.
* 'xpub' is the signer xpub, as described by the 'fingerprint' and 'derivation' (validated, in the case of this unit's signer).
* 'path' is a path applied to the xpub, to yield the root signer for this multisig.  In most cases this is empty '[]'.
* Alternatively, the contents of the multisig wallet file as produced by several wallet apps (BlueWallet, Sparrow, Nunchuk etc.) can be passed.


.. _register_multisig_reply:

register_multisig reply
-----------------------

.. code-block:: cbor

    {
        "id": "6000000$",
        "result": true
    }

.. _get_registered_multisigs_request:

get_registered_multisigs request
--------------------------------

Call to fetch brief summary of any registered multisig wallets associated with the hw signer.

.. code-block:: cbor

    {
        "id": "42",
        "method": "get_registered_multisigs"
    }

.. _get_registered_multisigs_reply:

get_registered_multisigs reply
------------------------------

.. code-block:: cbor

    {
        "id": "42",
        "result": {
            "work-team": {
                "variant": "wsh(multi(k))",
                "sorted": true,
                "threshold": 2,
                "num_signers": 3
            },
            "family": {
                "variant": "sh(wsh(multi(k)))",
                "sorted": false,
                "threshold": 2,
                "num_signers": 3
            },
            "small_beans": {
                "variant": "sh(multi(k))",
                "sorted": true,
                "threshold": 2,
                "num_signers": 2
            },
        }
    }

.. _get_registered_multisig_request:

get_registered_multisig request
-------------------------------

Call to fetch signer details of any registered multisig wallets associated with the hw signer.
NOTE: the multisig wallet must have been registered with firmware v1.0.23 or later for the full signer details to be persisted and available.

.. code-block:: cbor

    {
        "id": "43",
        "method": "get_registered_multisig"
        "params": {
            "multisig_name": "busacct",
            "as_file": false
        }
    }

* If 'as_file' is true, the flat-file format as supported by several wallet apps is returned in a single string
* If 'as_file' is false, structured json is returned


.. _get_registered_multisig_reply:

get_registered_multisig reply
-----------------------------

.. code-block:: cbor

    {
        "id": "43",
        "multisig_name": "busacct",
        "multisig_file": "Name: MainWallet\nPolicy: 2 of 3\nFormat: P2WSH\nDerivation: m/48'/0'/0'/2\n\nB237FE9D: xpub6E8C7BX4c7qfTsX7urnXggcAyFuhDmYLQhwRwZGLD9maUGWPinuc9k96ejhEQ1DCk..."
    }

or:

.. code-block:: cbor

    {
        "id": "43",
        "multisig_name": "busacct",
        "descriptor": {
            "variant": "wsh(multi(k))",
            "sorted": true,
            "threshold": 2,
            "signers": [
                {
                    "fingerprint": <4 bytes>,
                    "derivation": [44, 2147483648, 2147483648],
                    "xpub": "tpubDDCNstnPhbdd4vwbw5UWK3vRQSF1WXQkvBHpNXpKJAkwFYjwu735EH3GVf53qwbWimzewDUv68MUmRDgYtQ1AU8FRCPkazfuaBp7LaEaohG",
                    "path": [3, 1]
                },
                {
                    "fingerprint": <4 bytes>,
                    "derivation": [2147483651, 2147483649, 1],
                    "xpub": "tpubDDExQpZg2tziZ7ACSBCYsY3rYxAZtTRBgWwioRLYqgNBguH6rMHN1D8epTxUQUB5kM5nxkEtr2SNic6PJLPubcGMR6S2fmDZTzL9dHpU7ka",
                    "path": [1]
                }
            ]
        }
    }

.. _register_otp_request:

register_otp request
--------------------

Request to register an OTP secret and its associated parameters, for subsequent fetching of OTP codes.

.. code-block:: cbor

    {
        "id": "405",
        "method": "register_otp",
        "params": {
            "name": "test_otp",
            "uri": "otpauth://totp/Green:jade@blockstream.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GreenWallet&digits=8&algorithm=SHA256"
        }
    }

.. _register_otp_reply:

register_otp reply
------------------

.. code-block:: cbor

    {
        "id": "405",
        "result": true
    }

.. _get_otp_code:

get_otp_code request
--------------------

Request to geta new OTP code for a previously registered OTP record.

.. code-block:: cbor

    {
        "id": "406",
        "method": "get_otp_code",
        "params": {
            "name": "test_otp"
        }
    }

.. _get_otp_code_reply:

get_otp_code reply
------------------

.. code-block:: cbor

    {
        "id": "406",
        "result": 74935634
    }

.. _get_xpub_request:

get_xpub request
----------------

Request to fetch an xpub for the given bip32 path, expressed as an array of (uint64) integers.

.. code-block:: cbor

    {
        "id": "404",
        "method": "get_xpub",
        "params": {
            "network": "mainnet",
            "path": [2147483697, 2147483648, 2147483648, 0, 143]
        }
    }

.. _get_xpub_reply:

get_xpub reply
--------------

.. code-block:: cbor

    {
        "id": "404",
        "result": "xpub661MyMwAqRbcGJMgtWQnZ6b8Nk1YE4RkR2sAT9ZE3ovUH95wH5UxY1qkg7aRC7MdQD7YMauTncJMMHyWdDmkCeKMMoVwzJoK5DbZHHhinUQ"
    }

.. _get_receive_address_request:

get_receive_address request
---------------------------

Request to fetch a Blockstream Green (multisig shield) address.

.. code-block:: cbor

    {
        "id": "T-1000",
        "method": "get_receive_address",
        "params": {
            "network": "mainnet",
            "subaccount": 2,
            "branch": 1,
            "pointer": 114,
            "recovery_xpub": None,
            "csv_blocks": 65535
        }
    }

* 'recovery_xpub' (normal string xpub) is used if the subaccount indicated is a '2of3' account (in which case 'csv_blocks' should be omitted).
* 'recovery_xpub' should be omitted if the subaccount type is not '2of3'.
* 'csv_blocks' should be omitted if the subaccount is not csv-enabled.

or:

Request to fetch a single-sig address for the given script type and bip32 path, expressed as an array of (uint64) integers.

.. code-block:: cbor

    {
        "id": "T-1000",
        "method": "get_receive_address",
        "params": {
            "network": "mainnet",
            "variant": "sh(wpkh(k))",
            "path": [2147483697, 2147483648, 2147483648, 0, 143]
        }
    }

* 'variant' indicates the script type used, and must be one of: 'pkh(k)', 'wpkh(k)', 'sh(wpkh(k))' or 'tr(k)'.

or:

Request to fetch a multisig-sig address for the given (previously registered) multisig record, and bip32 path suffixes.

.. code-block:: cbor

    {
        "id": "T-1000",
        "method": "get_receive_address",
        "params": {
            "network": "mainnet",
            "multisig_name": "small_beans",
            "paths": [
                [0, 43],
                [0, 14]
            ]
        }
    }

* 'multisig_name' identifies a multisig wallet previously registered on the Jade hw unit.
* 'paths' are the path suffixes to be applied to the xpubs in the multisig, in the order in which they were in the original registration.  NOTE: usually these paths will all be identical.


.. _get_receive_address_reply:

get_receive_address reply
-------------------------

* NOTE: The reply is not sent until the user has explicitly confirmed the address on the hw.

.. code-block:: cbor

    {
        "id": "T-1000",
        "result": "3A9HgJqKS5FZtGykWKuVBKyosFppojPPj5"
    }

.. _get_bip85_pubkey_request:

get_bip85_pubkey request
------------------------

Request to fetch a bip85-based deterministic key for a given type, key size and index.

NOTE: currently this call only supports 'RSA', with sizes 1024, 2048, 3072 and 4096.

NOTE: Uses current wallet seed and bip85 specification to produce deterministic entropy to initialise shake256 PRNG, used to create a deterministic key.
However, since there is no well-specified deterministic recipe for creating keys, this implementation output may differ from other deterministic key-generation algorithms.

.. code-block:: cbor

    {
        "id": "8",
        "method": "get_bip85_pubkey",
        "params": {
            "key_type": "RSA",
            "key_bits": 2048,
            "index": 1
        }
    }

* 'key_type' must be 'RSA'
* 'key_bits' must be one of 1024, 2048, 3072 or 4096.


.. _get_bip85_pubkey_reply:

get_bip85_pubkey reply
----------------------

.. code-block:: cbor

    {
        "id": "8",
        "result": <pem string>
    }

* 'result' is a public key pem string


.. _get_bip85_bip39_entropy_request:

get_bip85_bip39_entropy request
-------------------------------

Request to fetch bip85-based bip39 entropy, returned encrypted to the host.

.. code-block:: cbor

    {
        "id": "12",
        "method": "get_bip85_bip39_entropy",
        "params": {
            "num_words": 12,
            "index": 1,
            "pubkey": <33 bytes>
        }
    }

* 'num_words' is the number of words the entropy is required to produce.
* 'index' is the index to use in the bip32 path to calculate the entropy.
* 'pubkey' is the the host ephemeral pubkey used for reply encryption.


.. _get_bip85_bip39_entropy_reply:

get_bip85_bip39_entropy reply
-----------------------------

* NOTE: The reply is not sent until the user has explicitly confirmed exporting on the hw.

.. code-block:: cbor

    {
        "id": "12",
        "pubkey": <33 bytes>,
        "encrypted": <bytes>,
        "hmac": <32 bytes>,
    }

* 'pubkey' is Jade's ephemeral pubkey used for ecdh secret generation.
* 'encrypted' is the requested bip85-based bip39 entropy, AES-CBC-256
  encrypted with the key described below (including leading IV).
* 'hmac' is the hmac of the encrypted buffer, using the hmac key described
  below.

To decrypt the reply, derived a shared secret using `ECDC(privkey,reply pubkey)`,
where `privkey` is the private key for the request's `pubkey`. Create hash
`HMAC-SHA512(secret, "bip85_bip39_entropy")`. The encryption key is the
first 32 bytes of the result; the hmac key is the second 32 bytes.


.. _sign_bip85_digests_request:

sign_bip85_digests request
--------------------------

Request to sign sha256 digests with a bip85-based deterministic key for a given type, key size and index.

NOTE: currently this call only supports 'RSA', with sizes 1024, 2048, 3072 and 4096.

NOTE: Uses current wallet seed and bip85 specification to produce deterministic entropy to initialise shake256 PRNG, used to create a deterministic key.
However, since there is no well-specified deterministic recipe for creating keys, this implementation output may differ from other deterministic key-generation algorithms.
This key is then used to sign the digests passed.

.. code-block:: cbor

    {
        "id": "16",
        "method": "get_bip85_pubkey",
        "params": {
            "key_type": "RSA",
            "key_bits": 2048,
            "index": 1,
            "digests": [
                <32-bytes>,
                <32-bytes>,
                ...
            ]
        }
    }

* 'key_type' must be 'RSA'
* 'key_bits' must be one of 1024, 2048, 3072 or 4096.
* 'digests' must be an array of 32-byte digests
* The maximum number of digests that can be signed in a single call depends upon the key (and hence signature) size.
    key_bits    max digests
     1024        8
     2048        8
     3072        6
     4096        4


.. _sign_bip85_digests_reply:

sign_bip85_digests reply
------------------------

.. code-block:: cbor

    {
        "id": "16",
        "result": [
          <bytes>,
          <bytes>,
          ...
        ]
    }

* 'result' is an array of signatures, corresponding to the array of digests passed in.


.. _get_identity_pubkey_request:

get_identity_pubkey request
---------------------------

Request to fetch a pubkey for a given identity and index (see SLIP-0013).

NOTE: currently this call only supports 'ssh://' and 'gpg://' using nist256p1 (secp256r1)

.. code-block:: cbor

    {
        "id": "31415916",
        "method": "get_identity_pubkey",
        "params": {
            "identity": "ssh://jade@blockstream.com",
            "curve": "nist256p1",
            "index": 12,
            "type": "slip-0013"
        }
    }

* 'identity' should be an ssh:// or gpg:// uri
* 'curve' must be 'nist256p1'.
* 'index' is optional, and defaults to zero.
* 'index' can be supplied, to generate multiple keys for the same identity string.
* 'type' is a string which defines how the key will be derived, and must be 'slip-0013' for an identity pubkey, or 'slip-0017' for an ecdh pubkey.


.. _get_identity_pubkey_reply:

get_identity_pubkey reply
-------------------------

.. code-block:: cbor

    {
        "id": "31415916",
        "result": <65 bytes>
    }

* 'result' is an uncompressed EC public key point
* If 'type' is 'slip-0013', the returned key should be consistent with sign_identity_reply_ below.
* If 'type' is 'slip-0017', the returned key should be consistent with get_identity_shared_key_reply_ below.

.. _get_identity_shared_key_request:

get_identity_shared_key request
-------------------------------

Request to fetch a shared secret for an identity and a counterparty public key (see SLIP-0017).

NOTE: currently this call only supports 'ssh://' and 'gpg://' using nist256p1 (secp256r1)

.. code-block:: cbor

    {
        "id": "52",
        "method": "get_identity_shared_key",
        "params": {
            "identity": "gpg://Jade <jade@blockstream.com>",
            "curve": "nist256p1",
            "their_pubkey": <65 bytes>
            "index": 13
        }
    }

* 'identity' should be an ssh:// or gpg:// uri
* 'curve' must be 'nist256p1'.
* 'their_pubkey' is an uncompressed EC public key point
* 'index' is optional, and defaults to zero.
* 'index' can be supplied, to generate multiple keys for the same identity string.

.. _get_identity_shared_key_reply:

get_identity_shared_key reply
-----------------------------

* NOTE: The reply is not sent until the user has explicitly confirmed sharing the identity key on the hw.

.. code-block:: cbor

    {
        "id": "52",
        "result": <32 bytes>
    }

* 'result' is an ecdh shared secret for the passed identity and counterparty public key
* This should be consistent with get_identity_pubkey_reply_ (with a 'type' of 'slip-0017') above.

.. _sign_identity_request:

sign_identity request
---------------------

Request to sign to confirm identity, using RFC6979 (see SLIP-0013).

NOTE: currently this call only supports 'ssh://' and 'gpg://' using nist256p1 (secp256r1)

.. code-block:: cbor

    {
        "id": "50wtlyl",
        "method": "sign_identity",
        "params": {
            "identity": "ssh://jade@blockstream.com",
            "curve": "nist256p1",
            "challenge": <bytes>
            "index": 0
        }
    }

* 'identity' should be an ssh:// or gpg:// uri
* 'curve' must be 'nist256p1'.
* 'index' is optional, and defaults to zero.
* 'index' can be supplied, to generate multiple keys for the same identity string.

.. _sign_identity_reply:

sign_identity reply
-------------------

* NOTE: The reply is not sent until the user has explicitly confirmed signing on the hw.

.. code-block:: cbor

    {
        "id": "50wtlyl",
        "result": {
            "signature": <65 bytes>
            "pubkey": <65 bytes>
        }
    }

* 'signature' is the low-s signature, prefixed with 0x00
* 'pubkey' is an uncompressed EC public key point
* This should be consistent with get_identity_pubkey_reply_ (with a 'type' of 'slip-0013') above.

.. _sign_message_legacy_request:

sign_message request (legacy)
-----------------------------

Request to sign a message string the given bip32 path, using RFC6979.

* This flow should be considered legacy - 'anti-exfil' signatures should be preferred.  See sign_message_ae_request_.

.. code-block:: cbor

    {
        "id": "6979",
        "method": "sign_message",
        "params": {
            "message": "Message to sign",
            "path": [2147483697, 2147483648, 2147483648, 0, 143]
        }
    }

 or:

.. code-block:: cbor

    {
        "id": "6979",
        "method": "sign_message"
        "params": {
            "message_file": "signmessage m/84h/0h/0h/0/0 ascii:this is a test message"
        }
    }


.. _sign_message_legacy_reply:

sign_message reply (legacy)
---------------------------

* NOTE: The reply is not sent until the user has explicitly confirmed signing on the hw.

.. code-block:: cbor

    {
        "id": "6979",
        "result": "H/bXtGN8FhkaPkLwKCZf4+AISH+SrCRnwpBNXxMxO/W5QRMDPKqJAjJGnRMqO+RusL9fQwlG7EtMOhbITiBPxWs="
    }

* 'result' is a base64-encoded signature.

.. _sign_message_ae_request:

sign_message request (anti-exfil)
---------------------------------

Request to sign a message string the given bip32 path, using anti-exfil commitments (recommended).

.. code-block:: cbor

    {
        "id": "57",
        "method": "sign_message",
        "params": {
            "message": "Message to sign",
            "path": [2147483697, 2147483648, 2147483648, 0, 143],
            "ae_host_commitment": <32 bytes>
        }
    }

.. _sign_message_ae_reply:

sign_message reply (anti-exfil)
-------------------------------

* NOTE: The reply is not sent until the user has explicitly confirmed signing on the hw.

.. code-block:: cbor

    {
        "id": "57",
        "result": "<32 bytes>"
    }

* In the case of Anti-Exfil signing, the inital returned data is the 'signer commitment' bytes (which the caller can use later to verify the signature).

The caller must then send a 'get_signature' message, passing the 'host entropy'.

.. _sign_message_ae_get_signature_request:

get_signature request (sign-message)
------------------------------------

Request to fetch an Anti-Exfil signature, providing the 'host entropy'.

.. code-block:: cbor

    {
        "id": "64",
        "method": "get_signature",
        "params": {
            "ae_host_entropy": <32 bytes>
        }
    }

.. _sign_message_ae_get_signature_reply:

get_signature reply (sign_message)
----------------------------------

.. code-block:: cbor

    {
        "id": "64",
        "result": "H/bXtGN8FhkaPkLwKCZf4+AISH+SrCRnwpBNXxMxO/W5QRMDPKqJAjJGnRMqO+RusL9fQwlG7EtMOhbITiBPxWs="
    }

* 'result' is a base64-encoded signature.

.. _sign_tx_legacy_request:

sign_tx request (legacy)
------------------------

Request to sign transaction inputs using RFC6979.

.. warning:: Taproot inputs can not be signed with this flow and the request will error if any are present.

.. warning:: This legacy flow is **deprecated** and will be removed in a future release. See sign_tx_ae_request_ for the non-legacy flow supporting 'anti-exfil' signatures and taproot.

.. code-block:: cbor

    {
        "id": "86400",
        "method": "sign_tx",
        "params": {
            "network": "mainnet",
            "txn": <bytes>,
            "num_inputs": 2,
            "use_ae_signatures": false,
            "change": [
                null,
                {
                    "variant": "sh(wpkh(k))",
                    "path": [2147483697, 2147483648, 2147483648, 0, 143]
                },
                null
            ]
        }
    }

* 'txn' should be the raw txn bytes.
* 'num_inputs' is the number of input messages which will be sent - which must be equal to the number of inputs in the transaction 'txn'.
* 'change' is optional (or can be null) - if provided it should be an array with the same number of elements as there are tx outputs.
* 'change' elements should be null for most outputs, and only populated for the outputs Jade is to automatically verify belong to its wallet.
* If 'is_change' is set (or missing - if so it is assumed to be true) this output will not be shown to the user to verify.
* The populated 'change' element should contain the data used to generate the output script (see also get_receive_address_request_):

Blockstream Green address (multisig-shield):

.. code-block:: cbor

    {
        "path": [1, 1, 13]
        "recovery_xpub": None
        "csv_blocks": 65535
    }

* 'recovery_xpub' is required if the change is to a 2of3 subaccount, otherwise should be omitted.
* 'csv_blocks' is required for csv-enabled accounts, otherwise should be omitted.

single-sig:

.. code-block:: cbor

    {
        "variant": "sh(wpkh(k))",
        "path": [2147483697, 2147483648, 2147483648, 0, 143]
    }

multi-sig:

.. code-block:: cbor

    {
        "multisig_name": "small_beans",
        "paths": [ [0,1], [0,1] ]
    }

.. _sign_tx_legacy_reply:

sign_tx reply (legacy)
----------------------

* NOTE: The reply is not sent until the user has explicitly confirmed the outputs on the hw.

.. code-block:: cbor

    {
        "id": "86400",
        "result": true
    }

At this point, the details of the tx-inputs must be sent to Jade for signing.

.. _sign_tx_legacy_input_request:

sign_tx input request (legacy)
------------------------------

A batch of 'tx_input' messages should be sent to Jade - one for each tx input.

* NOTE: No replies will be sent until the entire batch has been processed and confirmed on Jade.

.. code-block:: cbor

    {
        "id": "86400000000",
        "method": "tx_input",
        "params": {
            "is_witness": false,
            "input_tx": <bytes>,
            "script": <bytes>,
            "path": [2147483697, 2147483648, 2147483648, 0, 34],
            "sighash": 2
        }
    }

* 'is_witness', 'script', 'path' and 'sighash' should be omitted if a signature for this input is not required.
* 'sighash' is optional, and defaults to 1 (SIGHASH_ALL)
* If provided, 'script' should be the script-sig/redeem-script required to satisfy the input utxo.
* 'input_tx' should be the streamed bytes of the txn which output the utxo being spent.
* NOTE: if this is the only input, and 'is_witness' is 'true', the 'input_tx' can (optionally) be replaced with a 'satoshi' element, eg: '"satoshi": 2200000'.

Once the entire batch (of 'tx_input' messages) has been sent, processed and confirmed on Jade, a batch of replies are sent.

.. _sign_tx_legacy_input_reply:

sign_tx input reply (legacy)
----------------------------

The batch of replies should contain the same number of messages as the number of 'tx_input' messages sent, and the order of replies corresponds to the order of input messages (order of inputs in the txn).

.. code-block:: cbor

    {
        "id": "86400000000",
        "result": <bytes>
    }

* 'result' will be the bytes for the signature for the corresponding input, in DER format with the sighash appended.
* 'result' will be empty, if no signature was required for this input.

.. _sign_tx_ae_request:

sign_tx request (anti-exfil)
----------------------------

This flow is required in order use optional Anti-Exfil signatures (recommended), or to sign taproot inputs.

The initial request is identical to sign_tx_legacy_request_, except the 'use_ae_signatures' field must be set to 'true'.

.. _sign_tx_ae_reply:

sign_tx reply (anti-exfil)
--------------------------

The initial reply is the same as in sign_tx_legacy_reply_.

.. code-block:: cbor

    {
        "id": "86400",
        "result": true
    }

At this point, the details of the tx-inputs must be sent to Jade for signing.

sign_tx input request (anti-exfil)
----------------------------------

As in sign_tx_legacy_input_request_, 'tx_input' messages should be sent to Jade - one for each tx input.

If an Anti-Exfil signature is required for an input, the message must include the 'ae_host_commitment'
field. Otherwise, 'ae_host_commitment' should be omitted or empty to produce a non Anti-Exfil signature.

.. code-block:: cbor

    {
        "id": "THX1138",
        "method": "tx_input",
        "params": {
            "is_witness": false,
            "input_tx": <bytes>,
            "script": <bytes>,
            "path": [2147483697, 2147483648, 2147483648, 0, 34],
            "sighash": 3,
            "ae_host_commitment": <32 bytes>
        }
    }

* If 'sighash' is omitted for a taproot input, it defaults to 0 (SIGHASH_DEFAULT). Otherwise it defaults to 1 (SIGHASH_ALL).
* NOTE: Taproot inputs do not currently support Anti-Exfil signatures and so 'ae_host_commitment' must be omitted or empty.
* NOTE: Unlike the legacy flow, the sign_tx_ae_input_reply_ will be sent as soon as the user confirms signing on the hw, and does not wait for all inputs to be sent.

.. _sign_tx_ae_input_reply:

sign_tx input reply (anti-exfil)
--------------------------------

.. code-block:: cbor

    {
        "id": "THX1138",
        "result": <32 bytes>
    }

* If an Anti-Exfil signature was requested for the input, 'result' will contain the 'signer commitment' bytes which the caller can use later to verify the signature.
* If no signature was requested, or 'ae_host_commitment' was omitted/empty in the request, then 'result' will be empty.

Once all 'tx_input' messages have been sent and replies received, the caller must then send a sign_tx_ae_get_signature_request_' message and await its reply for each input in turn.

.. _sign_tx_ae_get_signature_request:

get_signature request (sign_tx)
-------------------------------

Request to fetch a signature for a transaction input.

* If an Anti-Exfil signature was requested for the input, 'ae_host_entropy' must be provided.
* If no signature was requested, or 'ae_host_commitment' was omitted/empty in the request, then 'ae_host_entropy' must be omitted or empty.

.. code-block:: cbor

    {
        "id": "128",
        "method": "get_signature",
        "params": {
            "ae_host_entropy": <32 bytes>
        }
    }

* NOTE: The first reply is not sent until the user has explicitly confirmed signing on the hw.

After user confirmation, the corresponding sign_tx_ae_get_signature_reply_ is then sent immediately.
This differs from the legacy flow where all signature requests must be sent first and then all
signature replies are returned.

.. _sign_tx_ae_get_signature_reply:

get_signature reply (sign_tx)
-----------------------------

Contains the generated signature for an input, if any.

.. code-block:: cbor

    {
        "id": "128",
        "result": <bytes>
    }

* If a signature for a taproot input was requested, 'result' will contain the 64 or 65 byte BIP 0341 Schnorr signature.
* Otherwise, if a signature was requested, 'result' will contain the DER-encoded ECDSA signature with the sighash byte appended.
* If no signature was requested, then 'result' will be empty.

.. _sign_psbt_request:

sign_psbt request
-----------------

Request to append signatures to a passed psbt, using RFC6979.

.. code-block:: cbor

    {
        "id": "6979",
        "method": "sign_psbt",
        "params": {
            "network": "mainnet",
            "psbt": <psbt bytes>
        }
    }

* Any inputs requiring signatures from this wallet (as identified by fingerprint) are generated and appended to the passed psbt.

.. _sign_psbt_reply:

sign_psbt reply
---------------

* NOTE: The reply is not sent until the user has explicitly confirmed signing on the hw.

.. code-block:: cbor

    {
        "id": "6979",
        "seqnum": 1
        "seqlen": 4
        "result": <psbt bytes>
    }

* NOTE: 'seqnum' and 'seqlen' indicate if the data is complete.  If 'seqlen' is greater than 1, the caller will have to send 'get_extended_data' messages to fetch the complete data.  See get_extended_data_request_.
* 'result' is the input psbt updated with any generated signatures.
* NOTE: if 'get_extended_data' calls are needed, the bytes payload of the messages must be concatenated to yield the complete psbt.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
