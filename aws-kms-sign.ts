import { KMS } from 'aws-sdk';
import { keccak256 } from 'js-sha3';
import * as ethutil from 'ethereumjs-util';
import Web3 from 'web3';
import * as asn1 from 'asn1.js';
import * as BN from 'bn.js';
import { Transaction, TxData } from 'ethereumjs-tx';
import { TransactionReceipt } from 'web3-core/types';

const projectId = 'indodaxhsm';
const locationId = 'asia-southeast2';
const keyRingId = 'test2';
const keyId = 'test3';
const versionId = '1';
// Imports the Cloud KMS library
const {KeyManagementServiceClient} = require('@google-cloud/kms');
const pki = require('node-forge').pki;

// Instantiates a client
const client = new KeyManagementServiceClient({keyFilename: '/Users/indodax/Desktop/docker/testhsm/indodaxhsm-c1f6b79448b3.json'});

// Build the key version name
const versionName = client.cryptoKeyVersionPath(
    projectId,
    locationId,
    keyRingId,
    keyId,
    versionId
);

const EcdsaSigAsnParse = asn1.define('EcdsaSig', function(this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
    this.seq().obj(
        this.key('r').int(),
        this.key('s').int(),
    );
});

const EcdsaPubKey = asn1.define('EcdsaPubKey', function(this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
    this.seq().obj(
        this.key('algo').seq().obj(
            this.key('a').objid(),
            this.key('b').objid(),
        ),
        this.key('pubKey').bitstr()
    );
});

async function sign(msgHash, keyId) {
    // const params : KMS.SignRequest = {
    //     // key id or 'Alias/<alias>'
    //     KeyId: keyId,
    //     Message: msgHash,
    //     // 'ECDSA_SHA_256' is the one compatible with ECC_SECG_P256K1.
    //     SigningAlgorithm: 'ECDSA_SHA_256',
    //     MessageType: 'DIGEST'
    // };
    // const res = await kms.sign(params).promise();
    // return res;

    // Create a digest of the message. The digest needs to match the digest
    // configured for the Cloud KMS key.
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256');
    hash.update(msgHash);
    const digest = hash.digest();

    // Optional but recommended: Compute digest's CRC32C.
    const crc32c = require('fast-crc32c');
    const digestCrc32c = crc32c.calculate(digest);

    // Sign the message with Cloud KMS
    const [signResponse] = await client.asymmetricSign({
        name: versionName,
        digest: {
            sha256: digest,
        },
        digestCrc32c: {
            value: digestCrc32c,
        },
    });

    // Optional, but recommended: perform integrity verification on signResponse.
    // For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
    // https://cloud.google.com/kms/docs/data-integrity-guidelines
    if (signResponse.name !== versionName) {
        throw new Error('AsymmetricSign: request corrupted in-transit');
    }
    if (!signResponse.verifiedDigestCrc32c) {
        throw new Error('AsymmetricSign: request corrupted in-transit');
    }
    if (
        crc32c.calculate(signResponse.signature) !==
        Number(signResponse.signatureCrc32c.value)
    ) {
        throw new Error('AsymmetricSign: response corrupted in-transit');
    }

    // Example of how to display signature. Because the signature is in a binary
    // format, you need to encode the output before printing it to a console or
    // displaying it on a screen.
    const encoded = signResponse.signature.toString('base64');
    console.log(encoded);

    return signResponse;
}

async function getPublicKey(keyPairId: string) {
    // return kms.getPublicKey({
    //     KeyId: keyPairId
    // }).promise();
    const [publicKey] = await client.getPublicKey({
        name: versionName,
    });

    // Optional, but recommended: perform integrity verification on publicKey.
    // For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
    // https://cloud.google.com/kms/docs/data-integrity-guidelines
    const crc32c = require('fast-crc32c');
    if (publicKey.name !== versionName) {
        throw new Error('GetPublicKey: request corrupted in-transit');
    }
    if (crc32c.calculate(publicKey.pem) !== Number(publicKey.pemCrc32c.value)) {
        throw new Error('GetPublicKey: response corrupted in-transit');
    }
    let pubKey = publicKey.pem;
    let b64 = pubKey.replace(/(-----(BEGIN|END) PUBLIC KEY-----|[\n\r])/g, '')
    let der = Buffer.from(b64, 'base64');

    console.log(b64);

    return der;
}

function getEthereumAddress(publicKey: Buffer): string {
    console.log("Encoded Pub Key: " + publicKey.toString('hex'));

    // The public key is ASN1 encoded in a format according to
    // https://tools.ietf.org/html/rfc5480#section-2
    // I used https://lapo.it/asn1js to figure out how to parse this
    // and defined the schema in the EcdsaPubKey object
    let res = EcdsaPubKey.decode(publicKey, 'der');
    let pubKeyBuffer : Buffer = res.pubKey.data;

    // The public key starts with a 0x04 prefix that needs to be removed
    // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
    pubKeyBuffer = pubKeyBuffer.slice(1, pubKeyBuffer.length);

    const address = keccak256(pubKeyBuffer) // keccak256 hash of publicKey
    console.log(address);
    const buf2 = Buffer.from(address, 'hex');
    console.log(buf2);
    const EthAddr = "0x" + buf2.slice(-20).toString('hex'); // take last 20 bytes as ethereum adress
    console.log("Generated Ethreum address: " + EthAddr);
    return EthAddr;
}

async function findEthereumSig(plaintext) {
    let signature = await sign(plaintext, keyId);
    if (signature.signature == undefined) {
        throw new Error('Signature is undefined.');
    }
    console.log("encoded sig: " + signature.signature.toString('hex'));

    let decoded = EcdsaSigAsnParse.decode(signature.signature, 'der');
    let r : BN = decoded.r;
    let s : BN = decoded.s;
    console.log("r: " + r.toString(10));
    console.log("s: " + s.toString(10));

    let tempsig = r.toString(16) + s.toString(16);

    let secp256k1N = new BN("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16); // max value on the curve
    let secp256k1halfN = secp256k1N.div(new BN(2)); // half of the curve
    // Because of EIP-2 not all elliptic curve signatures are accepted
    // the value of s needs to be SMALLER than half of the curve
    // i.e. we need to flip s if it's greater than half of the curve
    if (s.gt(secp256k1halfN)) {
        console.log("s is on the wrong side of the curve... flipping - tempsig: " + tempsig + " length: " + tempsig.length);
        // According to EIP2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
        // if s < half the curve we need to invert it
        // s = curve.n - s
        s = secp256k1N.sub(s);
        console.log("new s: " + s.toString(10));
        return { r, s }
    }
    // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
    return { r, s }
}

function recoverPubKeyFromSig(msg: Buffer, r : BN, s : BN, v: number) {
    console.log("Recovering public key with msg " + msg.toString('hex') + " r: " + r.toString(16) + " s: " + s.toString(16));
    let rBuffer = r.toBuffer();
    let sBuffer = s.toBuffer();
    let pubKey = ethutil.ecrecover(msg, v, rBuffer, sBuffer);
    let addrBuf = ethutil.pubToAddress(pubKey);
    var RecoveredEthAddr = ethutil.bufferToHex(addrBuf);
    console.log( "Recovered ethereum address: " +  RecoveredEthAddr);
    return RecoveredEthAddr;
}

function findRightKey(msg: Buffer, r : BN, s: BN, expectedEthAddr: string) {
    // This is the wrapper function to find the right v value
    // There are two matching signatues on the elliptic curve
    // we need to find the one that matches to our public key
    // it can be v = 27 or v = 28
    let v = 27;
    let pubKey = recoverPubKeyFromSig(msg, r, s, v);
    if (pubKey != expectedEthAddr) {
        // if the pub key for v = 27 does not match
        // it has to be v = 28
        v = 28;
        pubKey = recoverPubKeyFromSig(msg, r, s, v)
    }
    console.log("Found the right ETH Address: " + pubKey + " v: " + v);
    return { pubKey, v };
}

txTest();
async function txTest() {
    const Web3 = require("web3");
    const web3 = new Web3(new Web3.providers.HttpProvider("https://ropsten.infura.io/v3/fa107db6b4df46bea6949b2ddb876c31"));

    let pubKey = await getPublicKey(keyId);
    let ethAddr = getEthereumAddress((pubKey));
    try {
        const address = web3.utils.toChecksumAddress(ethAddr);
        console.log(address);
    } catch(e) {
        console.error('invalid ethereum address', e.message);
    }
    let ethAddrHash = ethutil.keccak(Buffer.from(ethAddr));
    let sig = await findEthereumSig(ethAddrHash);
    let recoveredPubAddr = findRightKey(ethAddrHash, sig.r, sig.s, ethAddr);

    let gasprice_gwei = 10;
    let gasprice = gasprice_gwei * 1e9;

    const txParams: TxData = {
        nonce: await web3.eth.getTransactionCount(ethAddr),
        gasPrice: '0x' + gasprice.toString(16),
        gasLimit: 160000,
        to: '0xb32e27ae317f15378d632d6265a04b5585235135',
        value: '0x00',
        data: '0x00',
        r: sig.r.toBuffer(),
        s: sig.s.toBuffer(),
        v: recoveredPubAddr.v
    }

    console.log(txParams);

    const tx = new Transaction(txParams, {
        chain: 'ropsten',
    });

    let txHash = tx.hash(false);
    sig = await findEthereumSig(txHash);
    recoveredPubAddr = findRightKey(txHash, sig.r, sig.s, ethAddr);
    tx.r = sig.r.toBuffer();
    tx.s = sig.s.toBuffer();
    tx.v = new BN(recoveredPubAddr.v).toBuffer();
    console.log(tx.getSenderAddress().toString('hex'));

    // Send signed tx to ethereum network
    const serializedTx = tx.serialize().toString('hex');
    web3.eth.sendSignedTransaction('0x' + serializedTx)
    .on('confirmation', (confirmationNumber : number, receipt : TransactionReceipt) => {})
    .on('receipt', (txReceipt : TransactionReceipt) => {
        console.log("signAndSendTx txReceipt. Tx Address: " + txReceipt.transactionHash);
    })
    .on('error', error => console.log(error));
}
