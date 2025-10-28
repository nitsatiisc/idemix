package aries

import (
	"log"
	"math/big"

	"github.com/IBM/idemix/bccsp/schemes/idemixevm"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger/aries-bbs-go/bbs"
	"github.com/pkg/errors"
)

func MakeZr(s *math.Zr) *big.Int {
	return new(big.Int).SetBytes(s.Bytes())
}

func MakeG1Point(point *math.G1) idemixevm.ZKATVerifierG1Point {
	raw := point.Bytes()

	return idemixevm.ZKATVerifierG1Point{
		X: new(big.Int).SetBytes(raw[0:32]),
		Y: new(big.Int).SetBytes(raw[32:64]),
	}
}

func MakeG2Point(point *math.G2) idemixevm.ZKATVerifierG2Point {
	raw := point.Bytes()
	Ximg := new(big.Int).SetBytes(raw[:32])
	Xre := new(big.Int).SetBytes(raw[32:64])
	Yimg := new(big.Int).SetBytes(raw[64:96])
	Yre := new(big.Int).SetBytes(raw[96:128])
	g2Point := idemixevm.ZKATVerifierG2Point{
		X: [2]*big.Int{Ximg, Xre},
		Y: [2]*big.Int{Yimg, Yre},
	}
	return g2Point
}

func MakeProofG1(proof *bbs.ProofG1) idemixevm.ZKATVerifierProofG1 {
	responses := make([]*big.Int, len(proof.Responses))
	for i := range proof.Responses {
		responses[i] = MakeZr(proof.Responses[i])
	}

	return idemixevm.ZKATVerifierProofG1{
		Commitment: MakeG1Point(proof.Commitment),
		Responses:  responses,
	}

}

func MakeIdemixIssuerKey(ipk *IssuerPublicKey) idemixevm.ZKATVerifierIssuerPublicKey {
	ipkSol := idemixevm.ZKATVerifierIssuerPublicKey{}
	ipkSol.G = MakeG1Point(math.Curves[ipk.PKwG.H0.CurveID()].GenG1)
	ipkSol.K = MakeG2Point(math.Curves[ipk.PKwG.H0.CurveID()].GenG2)
	ipkSol.H0 = MakeG1Point(ipk.PKwG.H0)
	ipkSol.H = make([]idemixevm.ZKATVerifierG1Point, len(ipk.PKwG.H))
	for i := range ipk.PKwG.H {
		ipkSol.H[i] = MakeG1Point(ipk.PKwG.H[i])
	}
	ipkSol.W = MakeG2Point(ipk.PK.PointG2)
	ipkSol.MessageCount = uint32(ipk.N)
	return ipkSol
}

func MakeAttributes(attributes []types.IdemixAttribute) []idemixevm.ZKATVerifierIdemixAttribute {
	attrsSol := make([]idemixevm.ZKATVerifierIdemixAttribute, len(attributes))
	for i := range attributes {
		if attributes[i].Type == types.IdemixIntAttribute {
			attrsSol[i].AttributeType = 0
			value := big.NewInt(int64(attributes[i].Value.(int)))
			if value != nil {
				attrsSol[i].ValueInt = value
				attrsSol[i].ValueBytes = []byte{}
			} else {
				attrsSol[i].ValueInt = big.NewInt(0)
				attrsSol[i].ValueBytes = []byte{}
			}

		} else if attributes[i].Type == types.IdemixBytesAttribute {
			attrsSol[i].AttributeType = 1
			attr := attributes[i].Value.([]byte)
			if attr != nil {
				attrsSol[i].ValueBytes = attr
			} else {
				attrsSol[i].ValueBytes = []byte{}
			}
			attrsSol[i].ValueInt = big.NewInt(0)

		} else {
			attrsSol[i].AttributeType = 2
			attrsSol[i].ValueBytes = []byte{}
			attrsSol[i].ValueInt = big.NewInt(0)
		}
	}
	return attrsSol
}

func CreateInstance() (*backends.SimulatedBackend, any, *common.Address, *bind.TransactOpts, error) {
	key, _ := crypto.GenerateKey()
	auth, _ := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	alloc := map[common.Address]core.GenesisAccount{
		auth.From: {Balance: big.NewInt(1e18)}, // 1 ETH
	}
	sim := backends.NewSimulatedBackend(alloc, 8_000_000_000)

	// 2. Deploy
	addr, _, instance, err := idemixevm.DeployIdemixevm(auth, sim)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrapf(err, "failed to deploy evmzcat")
	}
	sim.Commit()
	log.Println("Contract at:", addr.Hex())
	return sim, instance, &addr, auth, nil
}
