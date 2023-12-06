# moko_signer

This is a POC to generate a valid DFU package to be flashed for the https://github.com/acalatrava/openhaystack_moko project. This POC uses fixed values for the `initPacket`. So if the original firmware binary changes the `initPacket` won't be valid. This should be addressed by using protobuf to generate a valid `initPacket`.

## Generate a valid DFU ZIP file (sign)
First you need to copy the private key from the accessory in OpenHaystack by right-click on it and selecting `Copy private key B64`.

The parameters needed are the `private.key`, the `firmware.bin` and the `base64 private key`.
```
❯ npm run signer -- --mode sign --privateKey ../private.key --firmwarePath ../firmware.bin --base64Key vedQnEUGLzEkVfSfqLaxobA+RihvVbFsrgQjzQ==
DFU Package generated successfully to ./dfu.zip
```
The generated `dfu.zip` file should be a valid package to be flashed. (NOT TESTED)

## Validate a DFU ZIP file (verify)
You can verify if a ZIP file is valid by issuing the following command:
```
❯ npm run signer -- --mode verify --privateKey ../private.key --dfuPackage dfu.zip
[OK] Firmware Hash verified
[OK] Signature verified
```