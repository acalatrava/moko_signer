const fs = require('fs');
const crypto = require('crypto');
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const AdmZip = require('adm-zip');
const ellipticcurve = require("starkbank-ecdsa");
const argv = require('yargs').argv;
const path = require('path');
const BigInt = require("big-integer");

/**
 * generateDFUPackage will generate a patched firmware in DFU format to upload to the Moko device
 * @param {String} privateKeyPath path of the private key used to sign the firmware
 * @param {String} firmwareFilePath path of the firmware file
 * @param {String} base64KeyData private key of the accessory in base64 format
 * @param {String} dfuPath path to write the DFU package
 */
async function generateDFUPackage(privateKeyPath, firmwareFilePath, base64KeyData, dfuPath) {
    try {
        // Step 1: Create the patched firmware
        const firmwareData = fs.readFileSync(firmwareFilePath);
        const patchedFirmware = await patchFirmware(firmwareData, base64KeyData);

        // Step 2: Generate the initPacket
        const initPacketHeader = Buffer.from([0x12, 0x8a, 0x01, 0x0a, 0x44, 0x08, 0x01, 0x12, 0x40]);
        let initPacket = Buffer.from([0x08, 0x01, 0x10, 0x34, 0x1a, 0x02, 0x83, 0x02, 0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x9c, 0x8d, 0x03, 0x42, 0x24, 0x08, 0x03, 0x12, 0x20]);

        // SHA256 of the patchedFirmware
        const sha256firmware = sha256(patchedFirmware);

        // Add the SHA256 in little endian
        initPacket = Buffer.concat([initPacket, Buffer.from([...sha256firmware].reverse())]);

        // Add fixed data
        initPacket = Buffer.concat([initPacket, Buffer.from([0x48, 0x00, 0x52, 0x04, 0x08, 0x01, 0x12, 0x00])]);

        // Assuming you have the private key in a file named private_key.pem
        const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

        // Step 3: Sign the package
        const signedData = signData(initPacket, privateKey);

        if (!signedData) {
            throw new Error('Unable to sign the data');
        }

        const signR = Buffer.from(signedData).subarray(0, 32);
        const signS = Buffer.from(signedData).subarray(32);

        // Add fixed data
        initPacket = Buffer.concat([initPacket, Buffer.from([0x10, 0x00, 0x1a, 0x40])]);

        // Add the signature in little endian
        initPacket = Buffer.concat([initPacket, Buffer.from([...signR].reverse()), Buffer.from([...signS].reverse())]);

        // Prepend the header
        const finalInitPacket = Buffer.concat([initPacketHeader, initPacket]);

        // Write initPacket to a file
        fs.writeFileSync('/tmp/initpacket.dat', finalInitPacket);

        // Write patchedFirmware to a file
        fs.writeFileSync('/tmp/firmware.bin', patchedFirmware);

        // Create manifest JSON
        let manifest = `{
    "manifest": {
        "application": {
            "bin_file": "firmware.bin",
            "dat_file": "initpacket.dat"
        }
    }
}`;

        // Write manifest to a file
        fs.writeFileSync('/tmp/manifest.json', manifest);

        // Create a zip file
        const zip = new AdmZip();
        zip.addLocalFile('/tmp/initpacket.dat');
        zip.addLocalFile('/tmp/firmware.bin');
        zip.addLocalFile('/tmp/manifest.json');

        // Save the zip file
        zip.writeZip(dfuPath + `dfu.zip`);

        console.log('DFU Package generated successfully to ' + dfuPath + `dfu.zip`);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

/**
 * 
 * @param {Buffer} firmwareData 
 * @param {String} base64KeyData private key of the accessory
 * @returns {Buffer} patched firmware data
 */
async function patchFirmware(firmwareData, base64KeyData) {

    // Pattern to be patched
    const pattern = Buffer.from('OFFLINEFINDINGPUBLICKEYHERE!', 'ascii');

    // Decode the private key from base64
    const privateKey = Buffer.from(base64KeyData, 'base64');

    // Ensure the private key is the correct length
    if (privateKey.length !== 28) {
        throw new Error('Invalid private key length. Expected 28 bytes.');
    }

    // Derive the corresponding public key
    const ecdh = crypto.createECDH('secp224r1'); // P-224 curve
    ecdh.setPrivateKey(privateKey);
    const publicKey = ecdh.getPublicKey(undefined, 'compressed'); // Compressed format

    // Drop the first byte of the public key
    const key = publicKey.subarray(1);

    try {
        if (pattern.length !== key.length) {
            console.log("patternData.length ", pattern.length);
            console.log("keyData.length ", key.length);
            throw new Error('PatchingError: Inequal length of pattern and key');
        }

        const firmware = Buffer.from(firmwareData);
        let patchedFirmware = Buffer.from(firmware);
        let patchingSuccessful = false;

        // Find the position of the pattern
        for (let bytePosition = 0; bytePosition <= firmware.length - pattern.length; bytePosition++) {
            const potentialPattern = firmware.slice(bytePosition, bytePosition + pattern.length);

            if (potentialPattern.equals(pattern)) {
                // Found pattern. Replace in binary
                patchedFirmware.fill(key, bytePosition, bytePosition + pattern.length);
                patchingSuccessful = true;
            }
        }

        if (!patchingSuccessful) {
            throw new Error('PatchingError: Pattern not found');
        }

        return patchedFirmware;
    } catch (error) {
        throw error; // Rethrow the error for the calling function to handle
    }
}

/**
 * Generate a SHA256 hash
 * @param {Buffer} data to be hashed
 * @returns {Buffer} the SHA256 hash
 */
function sha256(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest();
}

/**
 * signData will sign the data passed using ECDSA
 * @param {Buffer} data to be signed
 * @param {String} privateKeyPem Private Key in PEM format
 * @returns {Buffer} Signature in P1363 format (R+S in hex)
 */
function signData(data, privateKeyPem) {
    var Ecdsa = ellipticcurve.Ecdsa;
    var PrivateKey = ellipticcurve.PrivateKey;

    let privateKey = PrivateKey.fromPem(privateKeyPem);
    let publicKey = privateKey.publicKey();

    const signature = Ecdsa.sign(data, privateKey);

    return Buffer.concat([Buffer.from(signature.r.toString(16), 'hex'), Buffer.from(signature.s.toString(16), 'hex')])
}

/**
 * verifyDFUPackage
 * @param {String} privateKeyPem private key in PEM format 
 * @param {String} firmwareDfuZipFilePath path for the zip DFU package to be verified
 */
async function verifyDFUPackage(privateKeyPem, firmwareDfuZipFilePath) {
    // Extract ZIP file to temporary location
    const tempDir = await extractZipToTemp(firmwareDfuZipFilePath);

    // Read manifest
    const manifest = await readJsonFile(tempDir + "/manifest.json");

    // Read firmware
    const firmwareData = fs.readFileSync(tempDir + "/" + manifest.manifest.application.bin_file);

    // Generate hash of firmware
    const sha256firmware = sha256(firmwareData);

    // Read initPacket
    const initPacket = fs.readFileSync(tempDir + "/" + manifest.manifest.application.dat_file);

    // Extract hash from initPacket
    const initPacketFirmwareHash = initPacket.subarray(33, 33 + 32);

    // Verify hash
    if (sha256firmware.reverse().equals(initPacketFirmwareHash)) {
        console.log("[OK] Firmware Hash verified");
    } else {
        console.log("[ERR] Firmware Hash are not equal");
    }

    // Read privateKey
    var Ecdsa = ellipticcurve.Ecdsa;
    var PrivateKey = ellipticcurve.PrivateKey;
    var Signature = ellipticcurve.Signature;
    let privateKey = PrivateKey.fromPem(privateKeyPem);
    let publicKey = privateKey.publicKey();

    // Extract signature from initPacket
    const initPacketSignature = initPacket.subarray(initPacket.length - 64);

    // Get R and S
    const hexR = initPacketSignature.subarray(0, 32).reverse();
    const hexS = initPacketSignature.subarray(32).reverse();

    // Convert them to BigInt
    const initPacketSignatureR = BigInt(hexR.toString('hex'), 16);
    const initPacketSignatureS = BigInt(hexS.toString('hex'), 16);

    // Initialize Signature object
    const signature = new Signature(initPacketSignatureR, initPacketSignatureS);

    // Extract data to be verified
    const signedInitPacket = initPacket.subarray(9, initPacket.length - 64 - 4);

    // Verify signature
    const ver = Ecdsa.verify(signedInitPacket, signature, publicKey);
    if (ver) {
        console.log("[OK] Signature verified");
    } else {
        console.log("[ERR] Signature is not valid");
    }

    // Delete temporary directory
    deleteDirectoryRecursive(tempDir);
}


/**
 * Extracts a zip file to a temporary location.
 * @param {string} zipFilePath - Path to the zip file.
 * @returns {Promise<string>} - Path to the extracted folder.
 */
async function extractZipToTemp(zipFilePath) {
    return new Promise((resolve, reject) => {
        try {
            // Create a unique temporary directory
            const tempDir = path.join(__dirname, 'temp', Date.now().toString());
            fs.mkdirSync(tempDir, { recursive: true });

            // Extract the zip file
            const zip = new AdmZip(zipFilePath);
            zip.extractAllTo(tempDir, true);

            resolve(tempDir);
        } catch (error) {
            reject(error);
        }
    });
}

/**
 * Read and parse a JSON file.
 * @param {string} filePath - Path to the JSON file.
 * @returns {Promise<object>} - Parsed JSON object.
 */
async function readJsonFile(filePath) {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                reject(err);
                return;
            }

            try {
                const jsonObject = JSON.parse(data);
                resolve(jsonObject);
            } catch (parseError) {
                reject(parseError);
            }
        });
    });
}

/**
 * Recursively deletes a directory and its contents.
 * @param {string} dirPath - Path to the directory to be deleted.
 */
function deleteDirectoryRecursive(dirPath) {
    if (fs.existsSync(dirPath)) {
        fs.readdirSync(dirPath).forEach((file) => {
            const curPath = path.join(dirPath, file);

            if (fs.lstatSync(curPath).isDirectory()) {
                // Recursive call for directories
                deleteDirectoryRecursive(curPath);
            } else {
                // Delete files
                fs.unlinkSync(curPath);
            }
        });

        // Remove the empty directory
        fs.rmdirSync(dirPath);
    }
}

const mode = argv.mode || '';
const privateKey = argv.privateKey || '';
const firmwarePath = argv.firmwarePath || '';
const base64Key = argv.base64Key || '';
const dfuPackage = argv.dfuPackage || '';
const dfuPath = argv.dfuPath || './';

if (mode != 'sign' && mode != 'verify') {
    console.error('Usage: npm run signer -- --mode <sign|verify> --privateKey <privateKeyPath> [--firmwarePath <firmwareFilePath> --base64Key <base64 public key> --dfuPath <path>] [--dfuPackage <dfuZipPackagePathFile>]');
    process.exit(1);
}

if (mode == 'sign') {
    if (privateKey == '' || firmwarePath == '' || base64Key == '') {
        console.error('Usage: npm run signer -- --mode sign --privateKey <privateKeyPath> --firmwarePath <firmwareFilePath> --base64Key <base64 public key> [--dfuPath <path>]');
        process.exit(1);
    }

    generateDFUPackage(privateKey, firmwarePath, base64Key, dfuPath);
} else {
    if (privateKey == '' || dfuPackage == '') {
        console.error('Usage: npm run signer -- --mode verify --privateKey <privateKeyPath> --dfuPackage <dfuZipPackagePathFile>');
        process.exit(1);
    }

    verifyDFUPackage(fs.readFileSync(privateKey, 'utf8'), dfuPackage);
}
