# SM2 2023 Cryptographic Suite

An implementation of the SM2 2023 cryptographic suite for Data Integrity, compliant with W3C standards and optimized for both Node.js and browser environments.

## Overview

The SM2 2023 Cryptographic Suite provides a standards-compliant implementation for:

- **Data Integrity Proofs**: Create and verify proofs using SM2 signatures
- **Document Canonicalization**: URDNA2015 algorithm implementation
- **SM2/SM3**: Signature generation and verification using SM2 with SM3 digest
- **Cross-Platform**: Consistent behavior across Node.js and browsers

## Features

- Complete SM2 2023 cryptographic suite implementation
- W3C Data Integrity 1.0 compatibility
- URDNA2015 document canonicalization
- Pluggable key management support
- Comprehensive error handling

## Standards Compliance

### Cryptographic Standards
- **GB/T 32918.1-2016**: SM2 Elliptic Curve Digital Signature Algorithm
- **GB/T 32905-2016**: SM3 Cryptographic Hash Algorithm

### W3C Standards
- **Data Integrity 1.0**
  - Proof creation and verification
  - Document canonicalization
  - Signature suite specification

## Installation

```bash
npm install @instun/sm2-2023-cryptosuite
```

## Usage

```javascript
import { cryptosuite } from '@instun/sm2-2023-cryptosuite';

// Initialize suite with a key
const suite = {
  ...cryptosuite,
  signer: () => key.signer(),
  verifier: () => key.verifier()
};

// Create a proof
const proof = await createProof({
  document,
  suite,
  purpose
});

// Verify a proof
const result = await verifyProof({
  document,
  proof,
  suite,
  purpose
});
```

## API Documentation

### Cryptographic Suite

Core implementation of the SM2 2023 cryptographic suite.

#### Properties

- `name`: 'sm2-2023'
- `requiredAlgorithm`: 'SM2'

#### Methods

##### canonize(input, options)
Canonicalizes a JSON-LD document.
- **Parameters:**
  - `input` (Object|string): JSON-LD document
  - `options` (Object, optional): Canonicalization options
- **Returns:** Promise<string> Canonicalized document

##### createVerifier(options)
Creates a verifier for SM2 signatures.
- **Parameters:**
  - `options.verificationMethod` (Object): Verification method object
- **Returns:** Verifier object with verify() method

### Error Handling

The module provides specific error types:
- `ArgumentError`: Invalid argument errors
- `FormatError`: Format conversion errors
- `CryptoError`: Cryptographic operation errors

Each error includes:
- Descriptive message
- Error code
- Original error cause (when applicable)

## Platform Requirements

- Node.js 16.x or later
- Modern browsers with ES6+ support

## License

Copyright (c) 2024 Instun, Inc. All rights reserved.
