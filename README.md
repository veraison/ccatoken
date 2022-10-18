# ccatoken

This repository is an implementation of the Confidential Computing Architecture (CCA) Attestation Token Library.

This work is based on the Attestation Token as detailed by the [Realm Management Monitor Specificiation (RMM)](https://developer.arm.com/documentation/den0137/latest)

The package allows to:

* Construct CCA Evidence by separately setting the CCA platform and Realm claims.

* Sign and serialise the CCA token to CBOR

* Decode a CBOR-encoded CCA token

* Verify the CCA token