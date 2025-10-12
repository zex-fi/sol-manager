import {ed25519 as frost} from "frost-lib";

export function generateParticipantsList(maxSigners: number): string[] {
	return Array.from({length: maxSigners}, (v, i) => frost.numToIdentifier(i+1));
}

export function keyGen(maxSigners: number, minSigners: number) {
	let {shares, pubkey_package: pubkeyPackage} = frost.keysGenerateWithDealer(maxSigners, minSigners);

	let keyPackages = {};
	for(let [identifier, secretShare] of Object.entries(shares)) {
	
		let keyPackage = frost.keyPackageFrom(secretShare);
		
		keyPackages[identifier] = keyPackage;
	}

	return {keyPackages, pubkeyPackage}
}

export function signFrost(message: Buffer, keyPackages, pubkeyPackage): string {
	let noncesMap = {};
	let commitmentsMap = {};
	for (let participantIdentifier of Object.keys(keyPackages)) {
		let keyPackage = keyPackages[participantIdentifier];
		let {nonces, commitments} = frost.round1Commit(keyPackage.signing_share);
		noncesMap[participantIdentifier] = nonces;
		commitmentsMap[participantIdentifier] = commitments;
	}

	let signatureShares = {};
	let signingPackage = frost.signingPackageNew(commitmentsMap, message.toString('hex'));
	for (let participantIdentifier of Object.keys(noncesMap)) {
		let keyPackage = keyPackages[participantIdentifier];
		let nonces = noncesMap[participantIdentifier];
		let signatureShare = frost.round2Sign(signingPackage, nonces, keyPackage);
		signatureShares[participantIdentifier] = signatureShare;
	}

	return frost.aggregate(signingPackage, signatureShares, pubkeyPackage);

}

export function verifyFrost(signature, message: Buffer, pubkeyPackage): boolean {
	return frost.verifyGroupSignature(signature, message.toString('hex'), pubkeyPackage);
}

if (require.main === module) {
	let minSigners = 3;
	let maxSigners = 5;

	let {keyPackages, pubkeyPackage} = keyGen(maxSigners, minSigners);
	console.log("publicKey: ", pubkeyPackage["verifying_key"])

	let message = Buffer.from("message to sign", 'utf-8');
	let wrongMessage = Buffer.from("a dummy message", 'utf-8');
	console.log(`message: "${message.toString()}"`, );

	let groupSignature = signFrost(message, keyPackages, pubkeyPackage);
	console.log("signature: ", groupSignature);

	// Check that the threshold signature can be verified by the group public
	// key (the verification key).
	let verified1 = verifyFrost(groupSignature, message, pubkeyPackage);
	let verified2 = verifyFrost(groupSignature, wrongMessage, pubkeyPackage);
		
	console.log("correct message verified: ", verified1);
	console.log("  wrong message verified: ", verified2);
}