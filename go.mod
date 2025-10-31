module github.com/IBM/idemix

go 1.24.0

require (
	github.com/IBM/idemix/bccsp/schemes/aries v0.0.0-20250313153527-832db18b9478
	github.com/IBM/idemix/bccsp/schemes/weak-bb v0.0.0-20250313153527-832db18b9478
	github.com/IBM/idemix/bccsp/types v0.0.0-20250313153527-832db18b9478
	github.com/IBM/mathlib v0.0.3-0.20250709075152-a138079496c3
	github.com/alecthomas/kingpin/v2 v2.4.0
	github.com/golang/protobuf v1.5.4
	github.com/hyperledger/aries-bbs-go v0.0.0-20240528084656-761671ea73bc
	github.com/hyperledger/fabric-protos-go-apiv2 v0.3.7
	github.com/onsi/ginkgo/v2 v2.26.0
	github.com/onsi/gomega v1.38.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.11.1
	github.com/sykesm/zap-logfmt v0.0.4
	go.uber.org/zap v1.27.0
	google.golang.org/grpc v1.76.0
)

replace github.com/consensys/gnark-crypto => github.com/consensys/gnark-crypto v0.18.0

require (
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/alecthomas/units v0.0.0-20240927000941-0f3dac36c52b // indirect
	github.com/bits-and-blooms/bitset v1.24.1 // indirect
	github.com/consensys/gnark-crypto v0.19.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20251007162407-5df77e3f7d1d // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20230602173724-9e02669dceb2 // indirect
	github.com/kilic/bls12-381 v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/hyperledger/aries-bbs-go => github.com/nitsatiisc/aries-bbs-go v0.0.0-20251026133707-5593848f603e
