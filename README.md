# ccatoken

This repository is an implementation of Confidential Computing Architecture (CCA) Attestation Token Library.

This work is based on the Attestation Token as detailed in Realm Management Monitor Specificiation [RMM Spec](https://developer.arm.com/documentation/den0137/a/?lang=en)

The package exposes the following functionalities:

* Construct CCA Evidence by setting the CCA platform and realm claims.

* Sign the claims to get the CCA token (as CBOR bytes)

* Get the CCA platform and realm claims from received CCA token

* Verify the CCA token