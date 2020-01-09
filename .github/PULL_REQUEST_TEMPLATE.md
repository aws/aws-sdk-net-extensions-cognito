*Issue #, if available:*
 
 Issue 44,
 Issue 28,
 Issue 10

*Description of changes:*
Fixes "Key already in dictionary" exception in StartWithSrpAuthAsync.
	Key is already being added earlier in authentication process, so to maintain existing logic, we simply use an indexer
	to 'add' the device key to the challenge auth response (Deeper fix could look at why it is being added twice)

Adds necessary logic to handle Device SRP authentication after a successful User SRP_AUTH and PASSWORD_VERIFIER.
	Within StartWithSrpAuthAsync, if the verifierResponse from the SrpPasswordVerifierAuthRequest is null, we attempt to respond
	to a "DEVICE_SRP_AUTH" challenge, as well as a "DEVICE_PASSWORD_VERIFIER" challenge. 

By submitting this pull request, I confirm that my contribution is made under the terms of the Apache 2.0 license.
