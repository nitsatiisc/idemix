// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

// This contract adds support for verifying zero knowledge proofs based on BN254 curve
// in fabric-token-sdk inside evm environment.
contract ZKATVerifier {
    // Seperator
    string public constant SEP = "||";
    // Sign label
    string public constant SIGN_LABEL = "sign";
    // BN254 scalar field group order
    uint256 public constant GROUP_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // BN254 base field prime
    uint256 public constant BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Representation of point on group G1
    struct G1Point { uint256 x; uint256 y; }

    // Representation of point on group G2
    struct G2Point {
        uint256[2] x;       // ximg, xreal
        uint256[2] y;       // yimg, yreal
    }


    // Solidity mimics of the IPA datastructures in token-sdk

    struct IPAVerifier {
        // inner product
        uint256 innerProduct;
        // Generator Q in affine
        G1Point Q;
        // left generators
        G1Point[] leftGenerators;
        // right generators
        G1Point[] rightGenerators;
        // commitment
        G1Point commitment;
        // rounds
        uint256 rounds;
    }

    struct IPAProof {
        // final folded left vector
        uint256 left;
        // final folded right vector
        uint256 right;
        // left messages during protocol rounds
        G1Point[] L;
        // right messages during protocol rounds
        G1Point[] R;
    }

    struct RangeVerifier {
        // commitment to the value
        G1Point comV;
        // generators for commitment
        G1Point g;
        G1Point h;
        // generators for vector commitments
        G1Point[] leftGenerators;
        G1Point[] rightGenerators;
        // generator for commitment to vector blinders
        G1Point P;
        // generator to be passed on to IPA
        G1Point Q;
        // number of rounds
        uint rounds;
        // number of bits in range
        uint nr;
    }

    struct RangeProof {
        // commitment to bit, bit - 1 vectors
        G1Point C;
        // commitment to blinders for above vectors
        G1Point D;
        // commitment to coeffs of polynomial t(X)
        G1Point T1;
        G1Point T2;
        // Blinding for value of inner product
        uint256 tau;
        // Correction to derive inner product commitment for IPA
        uint256 delta;
        // innerproduct for IPA
        uint256 innerProduct;
        // IPA proof
        IPAProof ipaProof;
    }

    // Solidity mimics of datastructures in idemix implementation in IBM/idemix
    struct IssuerPublicKey {
        G1Point g;              // generator of G1
        G2Point k;              // generator of G2
        G2Point w;              // this is the verification key
        G1Point h0;             // this is the generator corresponding to "s"
        G1Point [] h;           // these are generators for messages
        uint32 messageCount;    // number of messages supported.
    }

    struct IdemixAttribute {
        uint8 attributeType; // 0 = integer, 1 = bytes, 2 = hidden
        bytes valueBytes;    // byte attribute
        uint256 valueInt;    // int attribute
    }

    struct SignatureMessage {
        uint256 value;
        uint8 index;
    }

    struct ProofG1 {
        G1Point commitment;
        uint256[] responses;
    }

    struct PoKSignatureProof {
        G1Point aPrime;
        G1Point aBar;
        G1Point d;

        ProofG1 proofVC1;
        ProofG1 proofVC2;
    }

    // this is the main idemix proof
    struct IdemixSignatureProof {
        uint32 attrCount;               // number of attributes in credential
        uint8[] revealedAttributes;     // mask denoting revealed attributes
        // In the above, for now we assume that sk goes with h[0], so attr[i] goes with h[i+1]
        G1Point Nym;                    // pseudonym for secret key
        uint256 Nonce;                  // nonce
        PoKSignatureProof pokSignature; // main proof of knowledge of signature
        ProofG1 proofNym;               // linking proof for Nym
    }

    // Collect temporary variables in a struct to prevent
    // too many local variables error.
    struct tempVars {
        uint256 x;
        uint256 xprime;
        uint256 xinv;
        uint256 xsq;
        uint256 xinvsq;
        uint    n;
        G1Point Qprime;
        G1Point Cprime;
        G1Point X;
        G1Point tempLeft;
        G1Point tempRight;
        G1Point Cleft;
        G1Point Cright;
    }

    struct tempVarsRp {
        uint256 y;
        uint256 yinv;
        uint256 z;
        uint256 x;
        uint256 xsq;
        uint256 zsq;
        uint256 zcube;
        uint256 negz;
        uint256 f;
        uint256[] powers_of_y;
        uint256[] powers_of_two;
        G1Point lhs;
        G1Point rhs;
        G1Point ipaComm;
    }

    function testAttributes(IdemixAttribute[] memory attributes) external pure returns (uint256) {
        return attributes.length;
    }

    // All revealed messages are collected with their indices.
    // Revealed messages before sk, retain their original indices
    // Revealed messages after sk have their indices shifted by 1.
    // skIndex allows us to support secret key at any position.
    function attributesToSignatureMessages(IdemixAttribute[] memory attributes, uint8 skIndex)
    internal pure returns (SignatureMessage[] memory) {
        SignatureMessage[] memory sigMsgs = new SignatureMessage[](attributes.length);
        uint8 counter = 0;
        for (uint i = 0; i < attributes.length; i++) {
            if (attributes[i].attributeType == 0) {
                // Integer attribute
                sigMsgs[counter] = SignatureMessage(attributes[i].valueInt, uint8(i+1));
                counter++;
            } else if (attributes[i].attributeType == 1) {
                // Bytes attribute
                bytes memory hashBytes = abi.encodePacked(sha256(attributes[i].valueBytes));
                sigMsgs[counter] = SignatureMessage(hashtoZr(hashBytes), uint8(i+1));
                counter++;
            } else {
                // Hidden attribute
            }
        }

        // truncate sigMsgs to actual size
        SignatureMessage[] memory finalSigMsgs = new SignatureMessage[](attributes.length);
        for (uint i = 0; i < counter; i++) {
            finalSigMsgs[i] = sigMsgs[i];
        }

        return finalSigMsgs;
    }

    // mimic of similar function in idemix. Gets sigma protocol challenge
    function getChallengeBytes(
        IdemixSignatureProof memory proof,
        uint8[] memory revealedMsgs,
        IssuerPublicKey memory ipk)
        internal pure returns (bytes memory) {
        // This function would compute the challenge bytes for Idemix verification.
        bytes memory challengeBytes = abi.encodePacked(
            proof.pokSignature.aBar.x, proof.pokSignature.aBar.y,
            proof.pokSignature.aPrime.x, proof.pokSignature.aPrime.y,
            ipk.h0.x, ipk.h0.y,
            proof.pokSignature.proofVC1.commitment.x, proof.pokSignature.proofVC1.commitment.y,
            proof.pokSignature.d.x, proof.pokSignature.d.y,
            ipk.h0.x, ipk.h0.y
        );

        require(ipk.h.length >= revealedMsgs.length, "Insufficient Generators");
        for (uint8 i=0; i < revealedMsgs.length; i++) {
            if (revealedMsgs[i] != 1) {
                challengeBytes = abi.encodePacked(challengeBytes, ipk.h[i].x, ipk.h[i].y);
            }
        }

        challengeBytes = abi.encodePacked(challengeBytes, proof.pokSignature.proofVC2.commitment.x, proof.pokSignature.proofVC2.commitment.y);
        return challengeBytes;
    }

    // This function verifies the proof of knowledge of a valid BBS+ signature
    // proof - contains the proof of knowledge
    // ipk   - contains issuer public key with generators
    // proofChallenge - challenge "coming" from the outer function
    // sigMsgs - revealed messages and their indices w.r.t generators.
    function verifySignatureProof(
        IdemixSignatureProof memory proof,
        IssuerPublicKey memory ipk,
        uint256 proofChallenge,
        SignatureMessage[] memory sigMsgs
    ) internal view returns (bool) {

        // verify pairing
        bool result = pairingEq(proof.pokSignature.aPrime, ipk.w, proof.pokSignature.aBar, ipk.k);
        require(result, "pairing check failed");

        // verify proofVC1 : (-e).A' + (r2).h_0 = \bar{A}/d
        G1Point memory comm1 = ecSub(proof.pokSignature.aBar, proof.pokSignature.d);
        G1Point[] memory bases = new G1Point[](2);
        bases[0] = proof.pokSignature.aPrime;
        bases[1] = ipk.h0;
        G1Point memory left = ecMul(comm1, proofChallenge);
        left = ecMulVec(bases, proof.pokSignature.proofVC1.responses,left);
        require(left.x == proof.pokSignature.proofVC1.commitment.x, "proofVC1 failed");
        require(left.y == proof.pokSignature.proofVC1.commitment.y, "proofVC1 failed");

        // verify proofVC2: (-r3).d + (s').h0 + \sum_{i\in H} (m_i).h[i] = -(g1 + \sum_{i\in D} (m_i).h[i])
        uint hiddenAttrs = 0;
        for(uint i=0; i < proof.revealedAttributes.length; i++) {
            if (proof.revealedAttributes[i] == 0) {
                hiddenAttrs++;
            }
        }

        G1Point[] memory hiddenBases = new G1Point[](hiddenAttrs+2);
        hiddenBases[0] = proof.pokSignature.d;
        hiddenBases[1] = ipk.h0;

        hiddenAttrs = 0;
        for(uint i=0; i < proof.revealedAttributes.length; i++) {
            if (proof.revealedAttributes[i] == 0) {
                hiddenBases[2+hiddenAttrs] = ipk.h[i];
                hiddenAttrs++;
            }
        }
        require(hiddenBases.length == hiddenAttrs+2, "mismatch in hidden attributes and bases");

        // compute proofVC2 commitment
        G1Point memory comm2 = ipk.g;
        for(uint i=0; i < sigMsgs.length; i++) {
            comm2 = ecAdd(comm2, ecMul(ipk.h[sigMsgs[i].index], sigMsgs[i].value));
        }

        comm2 = negate(comm2);
        left = ecMul(comm2, proofChallenge);
        left = ecMulVec(hiddenBases, proof.pokSignature.proofVC2.responses, left);

        require(left.x == proof.pokSignature.proofVC2.commitment.x, "Invalid proofVC2");
        require(left.y == proof.pokSignature.proofVC2.commitment.y, "Invalid proofVC2");
        return true;
    }

    // The main function to verify idemix credential.
    function verifyIdeMixCred(
        IssuerPublicKey memory ipk,
        IdemixSignatureProof memory proof,
        bytes memory message,
        IdemixAttribute[] memory attributes,
        uint8 skIndex
    ) external view returns (bool) {
        require(attributes.length > 0, "attributes empty");
        require(ipk.h.length > 0, "ipk empty");
        require(attributes.length + 1 <= ipk.h.length, "Insufficient generators");
        bytes memory challengeBytes = abi.encodePacked("sign");

        SignatureMessage[] memory sigMsgs = attributesToSignatureMessages(attributes, skIndex);
        bytes memory hashBytes = getChallengeBytes(proof, proof.revealedAttributes, ipk);
        challengeBytes = abi.encodePacked(challengeBytes, hashBytes);

        challengeBytes = abi.encodePacked(challengeBytes,
            proof.Nym.x,
            proof.Nym.y,
            proof.proofNym.commitment.x,
            proof.proofNym.commitment.y
        );

        uint256 proofNonce = hashtoZr(abi.encodePacked(sha256(message)));
        challengeBytes = abi.encodePacked(challengeBytes, proofNonce);
        uint256 proofChallenge = hashtoZr(abi.encodePacked(sha256(challengeBytes)));

        challengeBytes = abi.encodePacked(proofChallenge, proof.Nonce);
        proofChallenge = hashtoZr(abi.encodePacked(sha256(challengeBytes)));

        // compare with responses
        // check correctness of Nym Proof
        G1Point[] memory bases = new G1Point[](2);
        bases[0] = ipk.h0;
        bases[1] = ipk.h[skIndex];
        G1Point memory left = ecMul(proof.Nym, proofChallenge);
        left = ecMulVec(bases, proof.proofNym.responses, left);
        require(left.x == proof.proofNym.commitment.x, "Incorrect Nym proof");
        require(left.y == proof.proofNym.commitment.y, "Incorrect Nym proof");

        // verify signature proof of knowledge
        bool result = verifySignatureProof(proof, ipk, proofChallenge, sigMsgs);
        return result;
    }



    // This function verifies proof for inner product v for vectors A and B.
    // IPAVerifier specifies size of the vectors, generators for left, right vectors and inner product and the commitment.
    // IPAProof contains the messages from the prover.
    function verifyIPA(IPAVerifier memory stmt, IPAProof memory proof) public view returns (bool) {
        require(proof.L.length == stmt.rounds, "Size of L != rounds");
        require(proof.R.length == stmt.rounds, "Size of R != rounds");
        tempVars memory temp;

        // compute initial challenge x by hashing generators, commitment and inner product.
        bytes memory rBytes = packPoints(stmt.rightGenerators);
        bytes memory lBytes = packPoints(stmt.leftGenerators);
        bytes memory array = abi.encodePacked(rBytes, lBytes, stmt.Q.x, stmt.Q.y, stmt.commitment.x, stmt.commitment.y);
        bytes memory raw = abi.encodePacked(array,stmt.innerProduct);
        bytes memory hashBytes = abi.encodePacked(sha256(raw));
        temp.x = hashtoZr(hashBytes);
        temp.xprime = mulmod(temp.x, stmt.innerProduct, GROUP_ORDER);
        temp.Qprime = ecMul(stmt.Q, temp.xprime);
        G1Point memory C = ecAdd(stmt.commitment, temp.Qprime);
        temp.X = ecMul(stmt.Q, temp.x);

        // copy the generators for reduction rounds
        G1Point[] memory leftGen = new G1Point[](stmt.leftGenerators.length);
        G1Point[] memory rightGen = new G1Point[](stmt.rightGenerators.length);
        for(uint256 i=0; i < leftGen.length; i++) {
            leftGen[i] = stmt.leftGenerators[i];
            rightGen[i] = stmt.rightGenerators[i];
        }

        // reduce the instance size in each round
        temp.n = leftGen.length;
        for(uint i=0; i < stmt.rounds; i++) {
            // compute challenge by hashing i^th prover message.
            bytes memory cBytes = abi.encodePacked(proof.L[i].x, proof.L[i].y, proof.R[i].x, proof.R[i].y);
            hashBytes = abi.encodePacked(sha256(cBytes));
            temp.x = hashtoZr(hashBytes);
            temp.xinv = inverse(temp.x);
            require(mulmod(temp.x, temp.xinv, GROUP_ORDER)==uint256(1), "INVFAULT");
            temp.xsq = mulmod(temp.x, temp.x, GROUP_ORDER);
            temp.xinvsq = mulmod(temp.xinv, temp.xinv, GROUP_ORDER);
            temp.Cprime = ecMul(proof.L[i], temp.xsq);
            temp.Cright = ecMul(proof.R[i], temp.xinvsq);
            temp.Cprime = ecAdd(temp.Cprime, temp.Cright);
            temp.Cprime = ecAdd(temp.Cprime, C);
            C = temp.Cprime;

            // fold the generators
            temp.n = temp.n/2;
            for(uint j=0; j < temp.n; j++) {
                leftGen[j] = ecMul(leftGen[j], temp.xinv);
                temp.tempLeft = ecMul(leftGen[j+temp.n], temp.x);
                leftGen[j] = ecAdd(leftGen[j], temp.tempLeft);

                rightGen[j] = ecMul(rightGen[j], temp.x);
                temp.tempRight = ecMul(rightGen[j+temp.n], temp.xinv);
                rightGen[j] = ecAdd(rightGen[j], temp.tempRight);
            }
        }

        temp.Cprime = ecMul(leftGen[0], proof.left);
        temp.tempRight = ecMul(rightGen[0], proof.right);
        G1Point memory XPrime = ecMul(temp.X, mulmod(proof.left, proof.right, GROUP_ORDER));
        temp.Cprime = ecAdd(temp.Cprime, temp.tempRight);
        temp.Cprime = ecAdd(temp.Cprime, XPrime);
        require(temp.Cprime.x == C.x, "Invalid IPA Proof");
        require(temp.Cprime.y == C.y, "Invalid IPA Proof");
        return true;
    }



    // This function verifies the range proof.
    function verifyRange(RangeVerifier calldata stmt, RangeProof calldata proof) external view returns (bool) {
        tempVarsRp memory temp;
        // compute challenges y as H(C||D||comV)
        bytes memory hashBytes = abi.encodePacked(
            sha256(
                abi.encodePacked(proof.C.x, proof.C.y, proof.D.x, proof.D.y, stmt.comV.x, stmt.comV.y)
            ));
        temp.y = hashtoZr(hashBytes);
        temp.yinv = inverse(temp.y);
        hashBytes = abi.encodePacked(sha256(abi.encodePacked(temp.y)));

        temp.z = hashtoZr(hashBytes);
        temp.zsq = mulmod(temp.z, temp.z, GROUP_ORDER);
        temp.zcube = mulmod(temp.z, temp.zsq, GROUP_ORDER);
        temp.negz = (GROUP_ORDER - (temp.z % GROUP_ORDER)) % GROUP_ORDER;

        G1Point[] memory rightGenPrime = computeNewGenerators(stmt.rightGenerators, inverse(temp.y));
        temp.f = computeDelta(temp.y,temp.z, stmt.nr);

        // compute challenge x as H(T1||T2)
        hashBytes = abi.encodePacked(sha256(abi.encodePacked(proof.T1.x, proof.T1.y, proof.T2.x, proof.T2.y)));
        temp.x = hashtoZr(hashBytes);
        temp.xsq = mulmod(temp.x, temp.x, GROUP_ORDER);

        // compute vectors y^n and 2^n
        temp.powers_of_two = computePowerVector(uint256(2), stmt.nr);
        temp.powers_of_y = computePowerVector(temp.y, stmt.nr);

        temp.rhs = ecMul(stmt.comV, temp.zsq);
        temp.rhs = ecAdd(temp.rhs, ecMul(stmt.g, temp.f));
        temp.rhs = ecAdd(temp.rhs, ecMul(proof.T1, temp.x));
        temp.rhs = ecAdd(temp.rhs, ecMul(proof.T2, temp.xsq));

        temp.lhs = ecMul(stmt.g, proof.innerProduct);
        temp.lhs = ecAdd(temp.lhs, ecMul(stmt.h, proof.tau));

        require(temp.lhs.x == temp.rhs.x, "Invalid rangeproof");
        require(temp.lhs.y == temp.rhs.y, "Invalid rangeproof");

        // Compute commitment for IPA
        temp.ipaComm = proof.C;
        temp.ipaComm = ecAdd(temp.ipaComm, ecMul(proof.D, temp.x));
        for(uint i=0; i < stmt.nr; ++i) {
            temp.ipaComm = ecAdd(temp.ipaComm, ecMul(stmt.leftGenerators[i], temp.negz));
            uint256 exp1 = mulmod(temp.z, temp.powers_of_y[i], GROUP_ORDER);
            uint256 exp2 = mulmod(temp.zsq, temp.powers_of_two[i], GROUP_ORDER);
            exp1 = addmod(exp1, exp2, GROUP_ORDER);
            temp.ipaComm = ecAdd(temp.ipaComm, ecMul(rightGenPrime[i], exp1));
        }
        // apply final correction of P^{-\delta}
        uint256 negdelta = (GROUP_ORDER - (proof.delta % GROUP_ORDER)) % GROUP_ORDER;
        temp.ipaComm = ecAdd(temp.ipaComm, ecMul(stmt.P, negdelta));
        IPAVerifier memory ipaVerifier = IPAVerifier(
            proof.innerProduct,
            stmt.Q,
            stmt.leftGenerators,
            rightGenPrime,
            temp.ipaComm,
            stmt.rounds
        );

        require(verifyIPA(ipaVerifier,proof.ipaProof), "Invalid IPA Proof");
        return true;
    }



    // This is a small test function to verify a simple Schnorr proof of g^x = P.
    function verifyDlog(
        uint256 Gx, uint256 Gy,
        uint256 Px, uint256 Py,
        uint256 Tx, uint256 Ty,
        uint256 prfZ
    ) external view returns (bool) {

        G1Point memory G = G1Point(Gx, Gy);
        G1Point memory P = G1Point(Px, Py);
        G1Point memory t = G1Point(Tx, Ty);
        // compute challenge c = Hash(G||P||t)
        bytes memory cBytes = abi.encodePacked(sha256(abi.encodePacked(Gx,Gy,Px,Py,Tx,Ty)));
        uint256 c = hashtoZr(cBytes);
        G1Point memory lhs = ecMul(G, prfZ);    // lhs = z.G
        G1Point memory rhs = ecMul(P, c);       // rhs = c.P + t
        rhs = ecAdd(rhs, t);
        require(lhs.x == rhs.x, "lhs.x != rhs.x");
        require(lhs.y == rhs.y, "lhs.y != rhs.y");
        return true;
    }

    // ECMUL precompile (0x07). Input: 32B x,32B y,32B scalar Output: 32B x,32B y
    function ecMul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        // reduce scalar mod group order to be safe
        s = s % GROUP_ORDER;

        bytes memory input = abi.encodePacked(p.x, p.y, s);
        bytes memory out = new bytes(64); // 2 * 32 bytes
        bool success;
        assembly {
        // 0x07 = ECMUL
        // call staticcall(gas, to, inOffset, inSize, outOffset, outSize)
            success := staticcall(gas(), 0x07, add(input, 0x20), 0x60, add(out, 0x20), 0x40)
        }
        require(success, "ecmul precompile failed");
        r.x = toUint256(out, 0) % BASE_FIELD;
        r.y = toUint256(out, 32) % BASE_FIELD;
    }

    // ECADD precompile (0x06). Input: 32B x1, 32B y1, 32B x2, 32B y2 Output: 32B x3, 32B y3
    function ecAdd(G1Point memory p, G1Point memory q) internal view returns (G1Point memory r) {
        bytes memory input = abi.encodePacked(p.x, p.y, q.x, q.y);
        bytes memory out = new bytes(64);
        bool success;
        assembly {
        // 0x06 = ECADD
            success := staticcall(gas(), 0x06, add(input,0x20), 0x80, add(out,0x20), 0x40)
        }
        require(success, "ecadd precompile failed");
        r.x = toUint256(out, 0) % BASE_FIELD;
        r.y = toUint256(out, 32) % BASE_FIELD;
    }

    /// Returns the negation of a point P(x,y) as (x, -y mod p)
    function negate(G1Point memory p)
    internal pure returns (G1Point memory)
    {
        if (p.x == 0 && p.y == 0) {
            return G1Point(0, 0);
        }
        return G1Point(p.x, BASE_FIELD - (p.y % BASE_FIELD));
    }

    /// Elliptic curve subtraction: r = p1 - p2 = p1 + (-p2)
    function ecSub(G1Point memory p1, G1Point memory p2)
    internal view returns (G1Point memory r)
    {
        G1Point memory negP2 = negate(p2);
        return ecAdd(p1, negP2);
    }

    // Convenience routine to hash bytes to Zr element.
    function hashtoZr(bytes memory b) pure internal  returns (uint256) {
        uint256 r = toUint256(b,0);
        r = r % GROUP_ORDER;
        return r;
    }

    // Convenience routine to compute scalar product over G1
    function ecMulVec(G1Point[] memory points, uint256[] memory scalars, G1Point memory initial) internal view returns (G1Point memory) {
        require(points.length == scalars.length, "Vector sizes mismatch in scalar product");

        G1Point memory sum = initial;
        for(uint32 i=0; i < points.length; i++) {
            sum = ecAdd(sum, ecMul(points[i], scalars[i]));
        }

        return sum;
    }

    // Pairing check. Checks e(x1,y1).e(-x2,y2)=1 equivalent to e(x1,y1)=e(x2,y2)
    function pairingEq(
        G1Point memory x1,
        G2Point memory y1,
        G1Point memory x2,
        G2Point memory y2
    ) internal view returns (bool) {
        G1Point memory negX2 = negate(x2);

        uint256[12] memory input = [
                        x1.x, x1.y,
                            y1.x[0], y1.x[1], y1.y[0], y1.y[1],
                        negX2.x, negX2.y,
                            y2.x[0], y2.x[1], y2.y[0], y2.y[1]
            ];

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(
                not(0),
                0x08,
                input,
                0x180, // 12 * 32 bytes = 384 bytes
                out,
                0x20
            )
        }
        require(success, "pairing precompile failed");

        // Precompile returns 1 if true, 0 otherwise
        return out[0] == 1;
    }

    /// A test function to check scalar multiplication.
    function verifyMul(
        uint256 Ax, uint256 Ay,
        uint256 Bx, uint256 By,
        uint256 w
    ) external view returns (bool) {
        G1Point memory A = G1Point(Ax, Ay);
        G1Point memory B = G1Point(Bx, By);
        G1Point memory R = ecMul(A, w);
        return (R.x == B.x && R.y == B.y);
    }

    /// read 32-byte big-endian word from `b` at offset `offset` (0..32..).
    function toUint256(bytes memory b, uint256 offset) internal pure returns (uint256) {
        require(b.length >= offset + 32, "out of range");
        uint256 x;
        assembly {
            x := mload(add(add(b, 0x20), offset))
        }
        return x;
    }

    // Convenience routine to flatten G1 elements to bytes.
    function packPoints(G1Point[] memory points) public pure returns (bytes memory) {
        bytes memory out;
        for (uint i = 0; i < points.length; i++) {
            out = bytes.concat(out, abi.encodePacked(points[i].x, points[i].y));
        }
        return out;
    }

    // Convenience routine to compute fresh generators for range proof
    function computeNewGenerators(G1Point[] memory gens, uint256 y) public view returns (G1Point[] memory) {
        uint256 ypow = 1;
        G1Point[] memory gensPrime = new G1Point[](gens.length);
        for(uint i=0; i < gens.length; ++i) {
            gensPrime[i] = ecMul(gens[i], ypow);
            ypow = mulmod(ypow, y, GROUP_ORDER);
        }

        return gensPrime;
    }

    // compute function f(y,z)=(z-z^2)\sum{y} - z^3(2^n-1)
    function computeDelta(uint256 y, uint256 z, uint n) public view returns (uint256) {
        uint256 zsq = mulmod(z, z, GROUP_ORDER);
        uint256 zcube = mulmod(zsq, z, GROUP_ORDER);
        uint256 sumy = modExp(y, n, GROUP_ORDER) - 1;
        uint256 sum2 = modExp(2, n, GROUP_ORDER) - 1;
        sumy = mulmod(sumy, inverse(y-1), GROUP_ORDER);
        uint256 t1 = mulmod(z, z-1, GROUP_ORDER);
        t1 = mulmod(t1, sumy, GROUP_ORDER);
        uint256 t2 = mulmod(zcube, sum2, GROUP_ORDER);
        t2 = addmod(t1, t2, GROUP_ORDER);
        t2 = (GROUP_ORDER - (t2 % GROUP_ORDER)) % GROUP_ORDER;
        return t2;
    }

    // compute power vector
    function computePowerVector(uint256 y, uint n) public pure returns (uint256[] memory) {
        uint256[] memory powers = new uint256[](n);
        uint256 acc = uint256(1);
        for(uint i=0; i < n; i++) {
            powers[i] = acc;
            acc = mulmod(acc, y, GROUP_ORDER);
        }
        return powers;
    }


    // Performs (base ^ exponent) % modulus using the modexp precompile.
    // All arguments are uint256 and returned result is uint256.
    function modExp(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) internal view returns (uint256 result) {
        require(modulus != 0, "modulus cannot be zero");

        // Each input length is 32 bytes (uint256)
        bytes memory input = abi.encodePacked(
            uint256(32),   // base length
            uint256(32),   // exponent length
            uint256(32),   // modulus length
            bytes32(base),
            bytes32(exponent),
            bytes32(modulus)
        );

        bytes memory output = new bytes(32);

        bool success;
        assembly {
        // call(modexp) = 0x05
            success := staticcall(
                gas(),
                0x05,
                add(input, 0x20),
                mload(input),
                add(output, 0x20),
                0x20
            )
        }
        require(success, "modexp failed");

        assembly {
            result := mload(add(output, 0x20))
        }
    }

    // Compute inverse of Zr element using precompile.
    function inverse(uint256 x) public view returns (uint256 inv) {
        uint256[6] memory input;
        input[0] = 0x20; // base length
        input[1] = 0x20; // exp length
        input[2] = 0x20; // mod length
        input[3] = x;
        input[4] = GROUP_ORDER - 2;
        input[5] = GROUP_ORDER;

        bytes memory output = new bytes(0x20);
        assembly {
            if iszero(staticcall(not(0), 0x05, input, 0xc0, add(output, 0x20), 0x20)) {
                revert(0, 0)
            }
        }
        inv = abi.decode(output, (uint256));
    }

    // This function is for debugging purposes. Sometimes we need to examine
    // values (such as challenges from hash) computed during verification,
    // if they match the ones in Go proofs. This converts uints to base 10 strings
    // which can be exposed via revert.
    function uintToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }


}
