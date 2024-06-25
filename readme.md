```
+-----------------------------------+
| Step 1: Generate Root CA          |
|                                   |
|  +-----------------------------+  |
|  | Generate Root CA private key|  |
|  | and save to PEM file        |  |
|  +-----------------------------+  |
|  | Generate self-signed Root CA|  |
|  | certificate and save to PEM |  |
|  | file                        |  |
|  +-----------------------------+  |
+-----------------------------------+

             |
             v

+-----------------------------------+
| Step 2: Generate Signing Key Pair |
|                                   |
|  +-----------------------------+  |
|  | Generate signing private key|  |
|  | and save to PEM file        |  |
|  +-----------------------------+  |
+-----------------------------------+

             |
             v

+-----------------------------------+
| Step 3: Generate Signing Cert     |
|                                   |
|  +-----------------------------+  |
|  | Generate CSR with signing   |  |
|  | private key                 |  |
|  +-----------------------------+  |
|  | Sign CSR with Root CA       |  |
|  | private key to create       |  |
|  | signing certificate         |  |
|  +-----------------------------+  |
|  | Save signing certificate to |  |
|  | PEM file                    |  |
|  +-----------------------------+  |
+-----------------------------------+

             |
             v

+-----------------------------------+
| Step 4: Sign Data Using Signing   |
| Private Key                       |
|                                   |
|  +-----------------------------+  |
|  | Load signing private key    |  |
|  | and certificate from PEM    |  |
|  +-----------------------------+  |
|  | Prepare data to be signed   |  |
|  +-----------------------------+  |
|  | Hash the data to be signed  |  |
|  +-----------------------------+  |
+-----------------------------------+

             |
             v

+-----------------------------------+
| Step 5: Create Detached CMS       |
| Signature with Signed Attributes  |
|                                   |
|  +-----------------------------+  |
|  | Create signed attributes    |  |
|  +-----------------------------+  |
|  | Create SignedData structure |  |
|  | with signed attributes      |  |
|  +-----------------------------+  |
|  | Sign the attributes with    |  |
|  | signing private key         |  |
|  [+-----------------------------+  |
|  | Wrap SignedData in ContentInfo| |
|  +-----------------------------+  |
|  | Save CMS structure to DER   |  |
|  | file                        |  |
|  +-----------------------------+  |
+-----------------------------------+

             |
             v

+-----------------------------------+
| Step 6: Verify Detached CMS       |
| Signature with Signed Attributes  |
|                                   |
|  +-----------------------------+  |
|  | Load CMS structure from DER |  |
|  | file                        |  |
|  +-----------------------------+  |
|  | Extract signer information  |  |
|  +-----------------------------+  |
|  | Extract signed attributes   |  |
|  +-----------------------------+  |
|  | Verify message digest       |  |
|  +-----------------------------+  |
|  | Extract signing certificate |  |
|  +-----------------------------+  |
|  | Convert signing certificate |  |
|  | to cryptography format      |  |
|  +-----------------------------+  |
|  | Get public key from signing |  |
|  | certificate                 |  |
|  +-----------------------------+  |
|  | Verify signature over signed|  |
|  | attributes                  |  |
|  +-----------------------------+  |
|  | Load Root CA certificate    |  |
|  +-----------------------------+  |
|  | Verify signing certificate  |  |
|  | against Root CA certificate |  |
|  +-----------------------------+  |
+-----------------------------------+
```
Run the following commands:

```sh
python generate_root_ca.py
python generate_ca_signed_key.py
python create_dms_detached.py
python verify.py
