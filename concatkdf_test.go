package concatkdf_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/golang-crypto/concatkdf"

	"github.com/stretchr/testify/require"
)

type TestVector struct {
	Z        string
	L        int
	Salt     string
	Info     string
	Expected string
}

func TestKey(t *testing.T) {
	t.Run("for SHA-1", func(t *testing.T) {
		for _, testVector := range vectors["SHA1"] {
			secret, err := hex.DecodeString(testVector.Z)
			require.Nil(t, err)
			info, err := hex.DecodeString(testVector.Info)
			require.Nil(t, err)
			expected, err := hex.DecodeString(testVector.Expected)
			require.Nil(t, err)

			key, err := concatkdf.Key(sha1.New, secret, string(info), testVector.L)
			require.Nil(t, err)
			require.Equal(t, expected, key)
		}
	})

	t.Run("for SHA-256", func(t *testing.T) {
		for _, testVector := range vectors["SHA256"] {
			secret, err := hex.DecodeString(testVector.Z)
			require.Nil(t, err)
			info, err := hex.DecodeString(testVector.Info)
			require.Nil(t, err)
			expected, err := hex.DecodeString(testVector.Expected)
			require.Nil(t, err)

			key, err := concatkdf.Key(sha256.New, secret, string(info), testVector.L)
			require.Nil(t, err)
			require.Equal(t, expected, key)
		}
	})

	t.Run("for SHA-512", func(t *testing.T) {
		for _, testVector := range vectors["SHA512"] {
			secret, err := hex.DecodeString(testVector.Z)
			require.Nil(t, err)
			info, err := hex.DecodeString(testVector.Info)
			require.Nil(t, err)
			expected, err := hex.DecodeString(testVector.Expected)
			require.Nil(t, err)

			key, err := concatkdf.Key(sha512.New, secret, string(info), testVector.L)
			require.Nil(t, err)
			require.Equal(t, expected, key)
		}
	})

	t.Run("for HMAC with SHA-256", func(t *testing.T) {
		for _, testVector := range vectors["HMAC-SHA256"] {
			secret, err := hex.DecodeString(testVector.Z)
			require.Nil(t, err)
			salt, err := hex.DecodeString(testVector.Salt)
			require.Nil(t, err)
			info, err := hex.DecodeString(testVector.Info)
			require.Nil(t, err)
			expected, err := hex.DecodeString(testVector.Expected)
			require.Nil(t, err)

			key, err := concatkdf.Key(func() hash.Hash { return hmac.New(sha256.New, salt) }, secret, string(info), testVector.L)
			require.Nil(t, err)
			require.Equal(t, expected, key)
		}
	})

	t.Run("for HMAC with SHA-512", func(t *testing.T) {
		for _, testVector := range vectors["HMAC-SHA512"] {
			secret, err := hex.DecodeString(testVector.Z)
			require.Nil(t, err)
			salt, err := hex.DecodeString(testVector.Salt)
			require.Nil(t, err)
			info, err := hex.DecodeString(testVector.Info)
			require.Nil(t, err)
			expected, err := hex.DecodeString(testVector.Expected)
			require.Nil(t, err)

			key, err := concatkdf.Key(func() hash.Hash { return hmac.New(sha512.New, salt) }, secret, string(info), testVector.L)
			require.Nil(t, err)
			require.Equal(t, expected, key)
		}
	})
}

var vectors = map[string][]TestVector{
	"SHA1": {
		{Z: "d09a6b1a472f930db4f5e6b967900744", L: 16, Info: "b117255ab5f1b6b96fc434b0", Expected: "b5a3c52e97ae6e8c5069954354eab3c7"},
		{Z: "343666c0dd34b756e70f759f14c304f5", L: 16, Info: "722b28448d7eab85491bce09", Expected: "1003b650ddd3f0891a15166db5ec881d"},
		{Z: "b84acf03ab08652dd7f82fa956933261", L: 16, Info: "3d8773ec068c86053a918565", Expected: "1635dcd1ce698f736831b4badb68ab2b"},
		{Z: "8cc24ca3f1d1a8b34783780b79890430", L: 16, Info: "f08d4f2d9a8e6d7105c0bc16", Expected: "b8e716fb84a420aed4812cd76d9700ee"},
		{Z: "b616905a6f7562cd2689142ce21e42a3", L: 16, Info: "ead310159a909da87e7b4b40", Expected: "1b9201358c50fe5d5d42907c4a9fce78"},
		{Z: "3f57fd3fd56199b3eb33890f7ee28180", L: 16, Info: "7a5056ba4fdb034c7cb6c4fe", Expected: "e51ebd30a8c4b8449b0fb29d9adc11af"},
		{Z: "fb9fb108d104e9f662d6593fc84cde69", L: 16, Info: "5faf29211c1bdbf1b2696a7c", Expected: "7a3a7e670656e48c390cdd7c51e167e0"},
		{Z: "237a39981794f4516dccffc3dda28396", L: 16, Info: "62ed9528d104c241e0f66275", Expected: "0c26fc9e90e1c5c5f943428301682045"},
		{Z: "b9b6c45f7279218fa09894e06366a3a1", L: 16, Info: "0f384339670aaed4b89ecb7e", Expected: "ee5fad414e32fad5d52a2bf61a7f6c72"},
		{Z: "08b7140e2cd0a4abd79171e4d5a71cad", L: 16, Info: "099211f0d8a2e02dbb5958c0", Expected: "6162f5142e057efafd2c4f2bad5985a1"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 2, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a2"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 4, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 6, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 8, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f4853"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 10, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 12, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 14, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493d"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 16, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 18, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759a"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 20, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac704"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 22, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbe"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 24, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 26, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 28, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 30, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf1050"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 32, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 34, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 36, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 38, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f3"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 40, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 42, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 44, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 46, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 48, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 50, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8b"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 52, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 54, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f22"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 56, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f227688"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 58, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f2276885abf"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 60, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f2276885abfbc3e"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 62, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f2276885abfbc3e811a"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 64, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f2276885abfbc3e811a568d"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 66, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f2276885abfbc3e811a568d480d"},
		{Z: "ebe28edbae5a410b87a479243db3f690", L: 68, Info: "e60dd8b28228ce5b9be74d3b", Expected: "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f2276885abfbc3e811a568d480d9192"},
		{Z: "d7e6", L: 16, Info: "0bbe1fa8722023d7c3da4fff", Expected: "31e798e9931b612a3ad1b9b1008faa8c"},
		{Z: "4646779d", L: 16, Info: "0bbe1fa8722023d7c3da4fff", Expected: "139f68bcca879b490e268e569087d04d"},
		{Z: "d9811c81d4c6", L: 16, Info: "0bbe1fa8722023d7c3da4fff", Expected: "914dc4f09cb633a76e6c389e04c64485"},
		{Z: "8838f9d99ec46f09", L: 16, Info: "0bbe1fa8722023d7c3da4fff", Expected: "4f07dfb6f7a5bf348689e08b2e29c948"},
		{Z: "3e0939b33f34e779f30e", L: 16, Info: "0bbe1fa8722023d7c3da4fff", Expected: "b42c7a98c23be19d1187ff960e87557f"},
		{Z: "f36230cacca4d245d303058c", L: 16, Info: "0bbe1fa8722023d7c3da4fff", Expected: "50f2068d8010d355d56c5e34aaffbc67"},
		{Z: "7005d32c3d4284c73c3aefc70438", L: 16, Info: "0bbe1fa8722023d7c3da4fff", Expected: "66fd712ccf5462bbd41e89041ea7ea26"},
		{Z: "c01c83150b7734f8dbd6efd6f54d7365", L: 16, Info: "0bbe1fa8722023d7c3da4fff", Expected: "5c5edb0ceda9cd0c7f1f3d9e239c67d5"},
		{Z: "da69f1dbbebc837480af692e7e9ee6b9", L: 16, Info: "9949", Expected: "33c83f54ed00fb1bccd2113e88550941"},
		{Z: "da69f1dbbebc837480af692e7e9ee6b9", L: 16, Info: "17144da6", Expected: "a999c28961424cab35ec06015e8c376a"},
		{Z: "da69f1dbbebc837480af692e7e9ee6b9", L: 16, Info: "dffdee1062eb", Expected: "4101ad50e626ed6f957bff926dfbb7db"},
		{Z: "da69f1dbbebc837480af692e7e9ee6b9", L: 16, Info: "9f365043e23b4648", Expected: "4d3e4b971b88771f229df9f564984832"},
		{Z: "da69f1dbbebc837480af692e7e9ee6b9", L: 16, Info: "a885a0c4567ddc4f96da", Expected: "bebbc30f5a83df5e9c9b57db33c0c879"},
		{Z: "da69f1dbbebc837480af692e7e9ee6b9", L: 16, Info: "c9d86183295bfe4c3d85f0fd", Expected: "87c947e45407db63eb94cbaa02d14e94"},
		{Z: "da69f1dbbebc837480af692e7e9ee6b9", L: 16, Info: "825fadce46964236a486732c5dad", Expected: "192370a85ff78e3c0245129d9b398558"},
		{Z: "da69f1dbbebc837480af692e7e9ee6b9", L: 16, Info: "5c0b5eb3ac9f342347d73d7a521723aa", Expected: "c7b7634fd809383e87c4b1b3e728be56"},
		{Z: "8d7a4e7d5cf34b3f74873b862aeb33b7", L: 8, Info: "", Expected: "6a5594f402f74f69"},
		{Z: "9b208e7ee1e641fac1dff48fc1beb2d2", L: 16, Info: "", Expected: "556ed67e24ac0c7c46cc432da8bdb23c"},
		{Z: "4d2572539fed433211da28c8a0eebac3", L: 24, Info: "", Expected: "5a4054c59c5b92814025578f43c1b79fe84968fc284e240b"},
		{Z: "4e1e70c9886819a31bc29a537911add9", L: 32, Info: "", Expected: "ddbfc440449aab4131c6d8aec08ce1496f2702241d0e27cc155c5c7c3cda75b5"},
		{Z: "68f144c952528e540c686dc353b766f2", L: 40, Info: "", Expected: "59ed66bb6f54a9688a0b891d0b2ea6743621d9e1b5cc098cf3a55e6f864f9af8a95e4d945d2f987f"},
		{Z: "b66c9d507c9f837fbe60b6675fdbf38b", L: 48, Info: "", Expected: "c282787ddf421a72fc88811be81b08d0d6ab66c92d1011974aa58335a6bbbd62e9e982bfae5929865ea1d517247089d2"},
		{Z: "34e730b49e46c7ed2fb25975a4cccd2d", L: 56, Info: "", Expected: "39e76e6571cb00740260b9070accbdcc4a492c295cbef33d9e37dac21e5e9d07e0f12dc7063d2172641475d4e08b8e3712fb26a10c8376b8"},
		{Z: "e340d87e2d7adbc1b95ec2dbdc3b82be", L: 64, Info: "", Expected: "a660c0037a53f76f1e7667043f5869348ad07ac0e272e615ce31f16d4ab90d4b35fe5c370c0010ce79aff45682c6fb8b97f9a05b7d40b5af3c62999a10df9c6d"},
	},
	"SHA256": {
		{Z: "afc4e154498d4770aa8365f6903dc83b", L: 16, Info: "662af20379b29d5ef813e655", Expected: "f0b80d6ae4c1e19e2105a37024e35dc6"},
		{Z: "a3ce8d61d699ad150e196a7ab6736a63", L: 16, Info: "ce5cd95a44ee83a8fb83f34c", Expected: "5db3455a22b65edfcfde3da3e8d724cd"},
		{Z: "a9723e56045f0847fdd9c1c78781c8b7", L: 16, Info: "e69b6005b78f7d42d0a8ed2a", Expected: "ac3878b8cf357976f7fd8266923e1882"},
		{Z: "a07a5e8df7ee1b2ce2a3d1348edfa8ab", L: 16, Info: "e22a8ee34296dd39b56b31fb", Expected: "70927d218b6d119268381e9930a4f256"},
		{Z: "a96d854ffd7c4e8b9ab491ff8a2acabd", L: 16, Info: "b9e4cbe6ca2a018cc693b9f4", Expected: "8bd2a8388991c8c52d9bc9bf23d33175"},
		{Z: "31f283068405c6ee0da5b2a794ab38b0", L: 16, Info: "ea5d5a28ffab464e4a6abe56", Expected: "8064c984ca27692c56a7547f516a21c7"},
		{Z: "9882d0aea07d2685e6e775c0d6134572", L: 16, Info: "5b640a72696150433673af90", Expected: "44a91eb7a4b995f4d95a915ab934d649"},
		{Z: "a66049ef3cde2677ba7e9b92cfb181e7", L: 16, Info: "e648e71d98115f9dab39dfbd", Expected: "b77889472c3cb716ba5b6d41925e1a9c"},
		{Z: "c46336baa6aeace9a7b62dffa0086ea5", L: 16, Info: "03e9f849be03ba938778f7a8", Expected: "9321023e710df7b70f0f13d246e0d8ce"},
		{Z: "41d801e6382de60c01be6a4e228e14b5", L: 16, Info: "47014b649dbaa70911cbcdc7", Expected: "0e9a234e2fbea75933191d3724992495"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 2, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 4, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c06652"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 6, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c066529825"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 8, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 10, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 12, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db3773"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 14, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a37"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 16, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 18, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 20, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 22, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 24, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 26, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a1"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 28, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 30, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a9"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 32, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 34, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 36, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 38, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f4964"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 40, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 42, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 44, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 46, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 48, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 50, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 52, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 54, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c81"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 56, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 58, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40ecd7"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 60, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40ecd74aed"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 62, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40ecd74aed8eda"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 64, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40ecd74aed8eda2b8a"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 66, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40ecd74aed8eda2b8a3c71"},
		{Z: "3f892bd8b84dae64a782a35f6eaa8f00", L: 68, Info: "ec3f1cd873d28858a58cc39e", Expected: "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40ecd74aed8eda2b8a3c714fa0"},
		{Z: "3643", L: 16, Info: "ec7299bc411e17d6a69bd4e7", Expected: "67bc327d9aaf7be2d24b3d04ee200535"},
		{Z: "f709c053", L: 16, Info: "ec7299bc411e17d6a69bd4e7", Expected: "e2305223697504e14db98c46de8e482e"},
		{Z: "608b4e33d581", L: 16, Info: "ec7299bc411e17d6a69bd4e7", Expected: "89463310ac075ff377ea55bfcd3d5994"},
		{Z: "0a84ed242b1158da", L: 16, Info: "ec7299bc411e17d6a69bd4e7", Expected: "fbce1495f765027bd10ff9258d0151bc"},
		{Z: "6c674b8881f505897e33", L: 16, Info: "ec7299bc411e17d6a69bd4e7", Expected: "615c855dfc324a3c1b64bbed08ac2c90"},
		{Z: "7155d18b30e4d5ca902246dd", L: 16, Info: "ec7299bc411e17d6a69bd4e7", Expected: "5e328cc84358d8196083e0e0bbe5a645"},
		{Z: "5c724d9ac88b096567d9af0906ec", L: 16, Info: "ec7299bc411e17d6a69bd4e7", Expected: "606ea439afb653e1219d494eea78a5e2"},
		{Z: "15ef0d4dbe8f3dc8e4a624c90263ab2a", L: 16, Info: "ec7299bc411e17d6a69bd4e7", Expected: "389c26a162eda5ea871de9c39a753a86"},
		{Z: "bea6c7a68878fd22ee7d3c3ac0a13f8e", L: 16, Info: "780e", Expected: "e6e42d58ec65de3c0939e63710328819"},
		{Z: "bea6c7a68878fd22ee7d3c3ac0a13f8e", L: 16, Info: "c60f1a00", Expected: "2d53688365bd90fc7fde4f9daa9de7c5"},
		{Z: "bea6c7a68878fd22ee7d3c3ac0a13f8e", L: 16, Info: "347c49e56de9", Expected: "1b6a4c52bc452bd36a761d8421995d3d"},
		{Z: "bea6c7a68878fd22ee7d3c3ac0a13f8e", L: 16, Info: "f4848a096cf55b93", Expected: "b73664c1946e2a09e5974ba4cce11031"},
		{Z: "bea6c7a68878fd22ee7d3c3ac0a13f8e", L: 16, Info: "349d1d0a3d3d38382a07", Expected: "2f7c9c5c626960451026f44f33dc9b32"},
		{Z: "bea6c7a68878fd22ee7d3c3ac0a13f8e", L: 16, Info: "eb9d8dde67c9d58d735f6841", Expected: "62cabee6515fcae408b33065111131d2"},
		{Z: "bea6c7a68878fd22ee7d3c3ac0a13f8e", L: 16, Info: "5bcd97f229c485a25cd64a5b24b8", Expected: "9a0e033ce4cea66fe57d545aada74559"},
		{Z: "bea6c7a68878fd22ee7d3c3ac0a13f8e", L: 16, Info: "de5590f1f3e767e4a6e559e0ccedd13e", Expected: "35b70fc2171815b8de78b141f177954d"},
		{Z: "07db7201a00698ff7c75fd3ea82fc923", L: 8, Info: "", Expected: "b172a899852a9ca0"},
		{Z: "9ce5457e4a0eecc1c8709f7ef37a32e9", L: 16, Info: "", Expected: "7d81e7d61acc06b90984ec4145469608"},
		{Z: "2e7f8916143a8594a4df730d516d7df8", L: 24, Info: "", Expected: "16846f8148d4d7c092ece973c9d29fc0b56b60baafb530e1"},
		{Z: "0d5ec89a68b1a7a0df9524543f4d70ef", L: 32, Info: "", Expected: "77bc949ea0d3dd5c8eb7eb84054060fa966e7ecd739fa1e6343f6d821622b445"},
		{Z: "c83e358e99a689c67db4fe39cf8f26e1", L: 40, Info: "", Expected: "7df641f83c47dc285f7faade0564d625006a47d91ea4a08cd7f70c99aaa07266690e25aaa1631479"},
		{Z: "dc83c92ba9ef3dacd58c06fb1a6fd042", L: 48, Info: "", Expected: "2775d7c3ffc19f407d8c5f8ee57a32570b4ce2e9aff249d5beac9bb0751abee87ff392a67b21fcb228d0fc900870e9bf"},
		{Z: "1dd60aecf2a1ae3957522acc4eba704c", L: 56, Info: "", Expected: "25425fc7b4175fd4ee18668a3b133ff64e662256723cf1b9db24bf2902338fd7bfa957f5f8973e87d4aba29fc1feac5c09ecd9e99c79bbd1"},
		{Z: "248bfce1dac2c860c43ef123ffe0ffff", L: 64, Info: "", Expected: "bd8917bf149a48da6b1f981443bec8b102241dc96d6d5a1a4046e2d97cb007d13d4655b1071b702d4025eec22e0cb17eb1657bf50b861f2aa35cb3ae4e21ca0b"},
	},
	"SHA512": {
		{Z: "108cf63318555c787fa578731dd4f037", L: 16, Info: "53191b1dd3f94d83084d61d6", Expected: "0ad475c1826da3007637970c8b92b993"},
		{Z: "35fa6d42e65014f04bdd80ff1404ab27", L: 16, Info: "506d9cfe967748d1e6f84bd9", Expected: "16739821c3b13dee57e24c092211ddd6"},
		{Z: "775e83546ce8b41a83656bd723d63c9e", L: 16, Info: "514f4d06bf8c1646aeae28fa", Expected: "0bce0e54a721367088495c0c4c0683f5"},
		{Z: "03f1dea7561b885a5601c6e75e405140", L: 16, Info: "1e366c4b697d20aa9a54d6f5", Expected: "56a2ac8f0eb55fdc4d8a891664edfbdb"},
		{Z: "dc8189da1a72036316f408e1a52adc8e", L: 16, Info: "6a35c08b579cda50e374094d", Expected: "d6e181b75533138c1cc58a8ccd4cfa95"},
		{Z: "ea64d4d3081bde2945e244957e5734be", L: 16, Info: "59e8d3a17ff6fc16dc73b2f6", Expected: "3ec734db432a9cd2aa9cac1de8fde7f9"},
		{Z: "ef23b25bb4889faaf9cb68b87bfc1a60", L: 16, Info: "e0d97c03e49d023480bc83bf", Expected: "c1994e8fc611c3eada7284a21c207e56"},
		{Z: "4df9510862e9bdd8dc82029dd995490b", L: 16, Info: "37e0e7e1f3387b08dfabc44b", Expected: "9997801db5907a1ceb2d86b9d20d2cae"},
		{Z: "1c28d2959df5b63fef881d672662654c", L: 16, Info: "6181ea24c3f926d1eebbc245", Expected: "9da8121948aad5f533d60b7c9e456fcc"},
		{Z: "90d1771eabe683aaaa894592218601b4", L: 16, Info: "211c7cdbf6f1c54be27b955c", Expected: "69da1c89a990384ec431e49aeeca79a4"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 2, Info: "830221b1730d9176f807d407", Expected: "b8c4"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 4, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 6, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 8, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 10, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 12, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 14, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a0671"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 16, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e37"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 18, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d82"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 20, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 22, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 24, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 26, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a207"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 28, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 30, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c61995"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 32, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 34, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 36, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 38, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a7212"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 40, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 42, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58c"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 44, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 46, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 48, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 50, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 52, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f7386"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 54, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f73863045"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 56, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f738630459090"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 58, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f73863045909054b2"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 60, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f73863045909054b2389e"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 62, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f73863045909054b2389e06ec"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 64, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f73863045909054b2389e06ec00fe"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 66, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f73863045909054b2389e06ec00fe318c"},
		{Z: "e65b1905878b95f68b5535bd3b2b1013", L: 68, Info: "830221b1730d9176f807d407", Expected: "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f73863045909054b2389e06ec00fe318cabd9"},
		{Z: "64c3", L: 16, Info: "203ea7f077072a56376e06eb", Expected: "f8eb9df6b9de2fedaaf26ef8524164ac"},
		{Z: "8836e13b", L: 16, Info: "203ea7f077072a56376e06eb", Expected: "d0fab0cc0c3008fb270832ca0ff12b46"},
		{Z: "23048e756d7f", L: 16, Info: "203ea7f077072a56376e06eb", Expected: "5b7088a839d679e1d442e4a7fdba34c3"},
		{Z: "93c025ba303c83c5", L: 16, Info: "203ea7f077072a56376e06eb", Expected: "de10ddc717ab97ac20bf253eadd23ddb"},
		{Z: "5318e356f8826e8ad841", L: 16, Info: "203ea7f077072a56376e06eb", Expected: "1e87608b3a198e7012b57e4ccf2f800f"},
		{Z: "06ac39e7d7dfef8e6294297b", L: 16, Info: "203ea7f077072a56376e06eb", Expected: "948d6324b4799152ee82688c46f57865"},
		{Z: "0972ef15aa0c4d0293c3f6186e4b", L: 16, Info: "203ea7f077072a56376e06eb", Expected: "1b2ad9bf41cf4eed6d6ba3b48e64670f"},
		{Z: "c07668620dc1339f31fcc56c2a727894", L: 16, Info: "203ea7f077072a56376e06eb", Expected: "c46a36850141febbb40998586b354d60"},
		{Z: "92fd278a407feea0bd800ce30a19f1bd", L: 16, Info: "d24e", Expected: "f82469b860d82f19a877c73a926228d7"},
		{Z: "92fd278a407feea0bd800ce30a19f1bd", L: 16, Info: "2ce6a6fa", Expected: "788c9a143eb741a75710a3b954a4cf7b"},
		{Z: "92fd278a407feea0bd800ce30a19f1bd", L: 16, Info: "ed1557487b6c", Expected: "577894545d33995c23aacdf5d2e4f406"},
		{Z: "92fd278a407feea0bd800ce30a19f1bd", L: 16, Info: "7495a1bb72fd3c2c", Expected: "7fbae36293c15620d819559175583a0d"},
		{Z: "92fd278a407feea0bd800ce30a19f1bd", L: 16, Info: "ded9e2f44680f3d24e12", Expected: "1f6e5bac6c13b4602a28f62219521baa"},
		{Z: "92fd278a407feea0bd800ce30a19f1bd", L: 16, Info: "d1add71a1bd731712e9bdd6e", Expected: "406aa807571baead6b40922cdabb2cdc"},
		{Z: "92fd278a407feea0bd800ce30a19f1bd", L: 16, Info: "359662f56377dd98d372531eb39f", Expected: "b3fb7c6747c20b06f18bb84b28ff5a01"},
		{Z: "92fd278a407feea0bd800ce30a19f1bd", L: 16, Info: "94f3090f2c30b987719708614aefff5f", Expected: "ba83356afa0b64d71ef128dd9640b1d3"},
		{Z: "cbd266277a4cfda84614fcef3bff9578", L: 8, Info: "", Expected: "11af834ae1914416"},
		{Z: "36f6280b4445e122581f2c665d490a12", L: 16, Info: "", Expected: "5bf8cdf7f64cf5f418e96f92cb55dd84"},
		{Z: "79ad4be997507be220a59361348fec0d", L: 24, Info: "", Expected: "1a3b522df1e33cc76ee18785375115ba672f1c3341eb3ab8"},
		{Z: "ebf319671eaccc6fc5c05d958d171594", L: 32, Info: "", Expected: "a9488567547c2a8e9ed16776e31c039241772a9ec7ccd71fda12e9bac9b21724"},
		{Z: "3ba979e9bc5e3ec7613036b6f51cd5aa", L: 40, Info: "", Expected: "3ef6daf95160705fdf21cdabac257b05fec1ab7cc96843258afc406e5bf7982710fa7b9352d416aa"},
		{Z: "da86e85b453b06ffb26ea44612d78511", L: 48, Info: "", Expected: "1e63864b8efdbacf2906d3f5574d8b6b3014422bf78079fb7f47823bd7011c42dc89d4771d6d21726ab4ce824f3e47f6"},
		{Z: "62b5168ccb4fbf363bb2551dca496247", L: 56, Info: "", Expected: "857a801b9f970f4f6b38848e87879f5311617c000ecd682577b2b917a847f485d0bf929e486c01c32c082c3b2478fb782d89d6edca0d45e3"},
		{Z: "cf955f1b674d052b4fb1c79309b3ad17", L: 64, Info: "", Expected: "4949a56cc6c9c112364aeba6baf5da19b1a2708229eea14ef5b14c2ecfdca0cf46e21dfc87f5d660e7608b16128ecf3fd79e84af5268b48d57b24379aef0e13a"},
	},
	"HMAC-SHA256": {
		{Z: "6ee6c00d70a6cd14bd5a4e8fcfec8386", L: 16, Salt: "532f5131e0a2fecc722f87e5aa2062cb", Info: "861aa2886798231259bd0314", Expected: "13479e9a91dd20fdd757d68ffe8869fb"},
		{Z: "cb09b565de1ac27a50289b3704b93afd", L: 16, Salt: "d504c1c41a499481ce88695d18ae2e8f", Info: "5ed3768c2c7835943a789324", Expected: "f081c0255b0cae16edc6ce1d6c9d12bc"},
		{Z: "98f50345fd970639a1b7935f501e1d7c", L: 16, Salt: "3691939461247e9f74382ae4ef629b17", Info: "6ddbdb1314663152c3ccc192", Expected: "56f42183ed3e287298dbbecf143f51ac"},
		{Z: "a72b0076221727eca4d3ef8f4d88ac96", L: 16, Salt: "397dc6807de2c1d5ba52e03c4e6c7a19", Info: "12379bd7873a7dbabe894ac8", Expected: "26c0f937e8ca337a859b6c092fe22b9a"},
		{Z: "0b09bf8ebe1e85a049174c521e35be64", L: 16, Salt: "313d29bbeaa5ac9e52278f7619d29d93", Info: "e2ac98de1486959bfc6363c0", Expected: "4bfdf78782a45e2a5858edb851c5783c"},
		{Z: "e907ad4fe811ee047af77e0c4418226a", L: 16, Salt: "5000ef57104ca2e86a5fec5883ea4ea8", Info: "c4ee443920f2b7542eee2a24", Expected: "06bfbd9571462c920a5a1b589c765383"},
		{Z: "608dae15fe8b906d2dc649815bdee148", L: 16, Salt: "742cc5a02a24d09c66fd9da0d0c571f6", Info: "ba60ff781e2756cba07f6524", Expected: "7f7f9e5d8f89a8edd10289f1d690f629"},
		{Z: "eb39e8dc7c40b906216108e2592bb6cd", L: 16, Salt: "af9f612da575c1afc8c4afff4ced34e1", Info: "84b7f0628df0cb22baaa279a", Expected: "5202576c69c6276daedf4916de250d19"},
		{Z: "4bac0c1a963b8cf6933beb2ad191a31e", L: 16, Salt: "debd24d71a1a7ae77f7e3aa24d939635", Info: "9e51c8593cec92c89e82439a", Expected: "ecb9889f9004f80716b56c44910f160c"},
		{Z: "8aa41e3c8076ea01ca6789dd18709a68", L: 16, Salt: "7c9dacc409cde7b05efdae07bd9973db", Info: "52651f0f2e858bbfbacb2533", Expected: "b8683c9a982e0826d659a1ab77a603d7"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 2, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 4, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d3"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 6, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d8"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 8, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d89102"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 10, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be0"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 12, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f2"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 14, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 16, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 18, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c504"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 20, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 22, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a1"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 24, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca6"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 26, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 28, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd99"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 30, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995de"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 32, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 34, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 36, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c710"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 38, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 40, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 42, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca9091"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 44, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 46, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab6"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 48, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 50, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2f355"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 52, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2f355b904"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 54, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2f355b904f9eb"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 56, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2f355b904f9eb0388"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 58, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2f355b904f9eb0388b5b7"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 60, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2f355b904f9eb0388b5b7fe19"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 62, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2f355b904f9eb0388b5b7fe193c95"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 64, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2f355b904f9eb0388b5b7fe193c9546d4"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 66, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2f355b904f9eb0388b5b7fe193c9546d45849"},
		{Z: "02b40d33e3f685aeae677ac344eeaf77", L: 68, Salt: "0ad52c9357c85e4781296a36ca72039c", Info: "c67c389580128f18f6cf8592", Expected: "be32e7d306d891028be088f213f9f947c50420d9b5a12ca69818dd9995dedd8e6137c7104d67f2ca90915dda0ab68af2f355b904f9eb0388b5b7fe193c9546d45849133d"},
		{Z: "f4e1", L: 16, Salt: "3638271ccd68a25dc24ecddd39ef3f89", Info: "348a37a27ef1282f5f020dcc", Expected: "3f661ec46fcc1e110b88f33ee7dbc308"},
		{Z: "253554e5", L: 16, Salt: "3638271ccd68a25dc24ecddd39ef3f89", Info: "348a37a27ef1282f5f020dcc", Expected: "73ccb357554ca44967d507518262e38d"},
		{Z: "e10d0e0bc95b", L: 16, Salt: "3638271ccd68a25dc24ecddd39ef3f89", Info: "348a37a27ef1282f5f020dcc", Expected: "c4f1cf190980b6777bb35107654b25f9"},
		{Z: "451f7f2c23c51326", L: 16, Salt: "3638271ccd68a25dc24ecddd39ef3f89", Info: "348a37a27ef1282f5f020dcc", Expected: "ddb2d7475d00cc65bff6904b4f0b54ba"},
		{Z: "0f27277ee800d6cc5425", L: 16, Salt: "3638271ccd68a25dc24ecddd39ef3f89", Info: "348a37a27ef1282f5f020dcc", Expected: "1100a6049ae9d8be01ab3829754cecc2"},
		{Z: "20438ff1f26390dbc3a1a6d0", L: 16, Salt: "3638271ccd68a25dc24ecddd39ef3f89", Info: "348a37a27ef1282f5f020dcc", Expected: "5180382f740444ada597197f98e73e1e"},
		{Z: "b74a149a161546f8c20b06ac4ed4", L: 16, Salt: "3638271ccd68a25dc24ecddd39ef3f89", Info: "348a37a27ef1282f5f020dcc", Expected: "44f676e85c1b1a8bbc3d319218631ca3"},
		{Z: "8aa7df46b8cb3fe47228494f4e116b2c", L: 16, Salt: "3638271ccd68a25dc24ecddd39ef3f89", Info: "348a37a27ef1282f5f020dcc", Expected: "ebb24413855a0a3249960d0de0f4750d"},
		{Z: "a678236b6ac82077b23f73a510c1d0e2", L: 16, Salt: "46ee4f36a4167a09cde5a33b130c6e1c", Info: "d851", Expected: "5dbe10ead8f81a81a29072eca4501658"},
		{Z: "a678236b6ac82077b23f73a510c1d0e2", L: 16, Salt: "46ee4f36a4167a09cde5a33b130c6e1c", Info: "b04da03c", Expected: "0a08d7616dcbec25a36f1936b82992ca"},
		{Z: "a678236b6ac82077b23f73a510c1d0e2", L: 16, Salt: "46ee4f36a4167a09cde5a33b130c6e1c", Info: "f9e8b47eade3", Expected: "84a29697445179b662d85dbc59bf8042"},
		{Z: "a678236b6ac82077b23f73a510c1d0e2", L: 16, Salt: "46ee4f36a4167a09cde5a33b130c6e1c", Info: "5b141bfa54fcf824", Expected: "be7660c840644cec84d67d95ba7ebf2d"},
		{Z: "a678236b6ac82077b23f73a510c1d0e2", L: 16, Salt: "46ee4f36a4167a09cde5a33b130c6e1c", Info: "736e7ddb856f0ba14744", Expected: "e3010b1fbcb02fd8baa8449ac71d0c62"},
		{Z: "a678236b6ac82077b23f73a510c1d0e2", L: 16, Salt: "46ee4f36a4167a09cde5a33b130c6e1c", Info: "c54320ff6e7d1a3b0b3aea00", Expected: "df0ac84982999cda676e4cbf707c42f0"},
		{Z: "a678236b6ac82077b23f73a510c1d0e2", L: 16, Salt: "46ee4f36a4167a09cde5a33b130c6e1c", Info: "37ab143e1b4ab61d0294ea8afbc7", Expected: "93eec7f4dda18b7e710dbbd7570ebd13"},
		{Z: "a678236b6ac82077b23f73a510c1d0e2", L: 16, Salt: "46ee4f36a4167a09cde5a33b130c6e1c", Info: "c3146575d2c60981511e700902fc2ac1", Expected: "e9125f77d699faa53d5bc48f3fc2f7d0"},
		{Z: "0031558fddb96e3db2e0496026302055", L: 16, Salt: "1ae1", Info: "97ed3540c7466ab27395fe79", Expected: "ddf7eedcd997eca3943d4519aaf414f4"},
		{Z: "0031558fddb96e3db2e0496026302055", L: 16, Salt: "3bda13b6", Info: "97ed3540c7466ab27395fe79", Expected: "ec783ca20501df3cacac5ab4adbc6427"},
		{Z: "0031558fddb96e3db2e0496026302055", L: 16, Salt: "c792f52e5876", Info: "97ed3540c7466ab27395fe79", Expected: "9303a2562e6f8c418e3fcc081b94bdcf"},
		{Z: "0031558fddb96e3db2e0496026302055", L: 16, Salt: "a9b7a64840d52633", Info: "97ed3540c7466ab27395fe79", Expected: "aab6b0dc19bae0dd7fa02391ac3d6ef1"},
		{Z: "0031558fddb96e3db2e0496026302055", L: 16, Salt: "8f62a3ec15cdf9b3522f", Info: "97ed3540c7466ab27395fe79", Expected: "1516d5ed7f46474d250408b0864647cf"},
		{Z: "0031558fddb96e3db2e0496026302055", L: 16, Salt: "55ed67cbdc98ed8e45214704", Info: "97ed3540c7466ab27395fe79", Expected: "38bf96a3d737a84dc10a835d340b6866"},
		{Z: "0031558fddb96e3db2e0496026302055", L: 16, Salt: "e4946aff3b2ab891b311234c77bc", Info: "97ed3540c7466ab27395fe79", Expected: "3ddd870471ff028a63c5f1bacc7e5b5c"},
		{Z: "0031558fddb96e3db2e0496026302055", L: 16, Salt: "91e8378de5348cea41f84c41e8546e34", Info: "97ed3540c7466ab27395fe79", Expected: "bf1eb0eab488b2393ad6a1c2eb804381"},
		{Z: "4ce16564db9615f75d46c6a9837af7ca", L: 8, Salt: "6199187690823def2037e0632577c6b1", Info: "", Expected: "0a102289b16cbf4b"},
		{Z: "2578fe1116e27e3a5e8e935e892e12eb", L: 16, Salt: "6199187690823def2037e0632577c6b1", Info: "", Expected: "dd5773998893ad5a93f9819c8e798aab"},
		{Z: "e9dd8bd75f29661e61703346bbf2df47", L: 24, Salt: "6199187690823def2037e0632577c6b1", Info: "", Expected: "32136643daa64aaac0e2886364f157ba923d7b36ada761eb"},
		{Z: "e4640d3752cf48186a8ad2d7d4a81210", L: 32, Salt: "6199187690823def2037e0632577c6b1", Info: "", Expected: "6379d59efbe02576663af5efaccb9d063f596a22c8e1fed12cde7cdd7f327e88"},
		{Z: "3bd9a074a219d62273c3f639659a3ecd", L: 40, Salt: "6199187690823def2037e0632577c6b1", Info: "", Expected: "cc45eb2ab80272c1e082b4f167ee4e086f12af3fbd0c812dda5568fea702928999cde3899cffc8a8"},
		{Z: "2147c0fb1c7587b22fa44ce3bf3d8f5b", L: 48, Salt: "6199187690823def2037e0632577c6b1", Info: "", Expected: "4e3a8827fcdb214686b35bfcc497ca69dccb78d3464aa4af0704ec0fba03c7bb10b9a4e31e27b1b2379a32e46935309c"},
		{Z: "2c2438b6321fed7a9eac200b91b3ac30", L: 56, Salt: "6199187690823def2037e0632577c6b1", Info: "", Expected: "b402fda16e1c2719263be82158972c9080a7bafcbe0a3a6ede3504a3d5c8c0c0e00fe7e5f6bb3afdfa4d661b8fbe4bd7b950cfe0b2443bbd"},
		{Z: "0ffa4c40a822f6e3d86053aefe738eac", L: 64, Salt: "6199187690823def2037e0632577c6b1", Info: "", Expected: "0486d589aa71a603c09120fb76eeab3293eee2dc36a91b23eb954d6703ade8a7b660d920c5a6f7bf3898d0e81fbad3a680b74b33680e0cc6a16aa616d078b256"},
		{Z: "a801d997ed539ae9aa05d17871eb7fab", L: 8, Info: "03697296e42a6fdbdb24b3ec", Expected: "1a5efa3aca87c1f4"},
		{Z: "e9624e112f9e90e7bf8a749cf37d920c", L: 16, Info: "03697296e42a6fdbdb24b3ec", Expected: "ee93ca3986cc43516ae4e29fd7a90ef1"},
		{Z: "a92acdee54a84a4564d4782d47801ec0", L: 24, Info: "03697296e42a6fdbdb24b3ec", Expected: "3116b87eaffaa0cc48a72e6c1574df335d706f7c860b44e9"},
		{Z: "e60d902e63b1a2bf5dab733cadb47b10", L: 32, Info: "03697296e42a6fdbdb24b3ec", Expected: "3fde6c078dd6dc65aacf62beafa39398d2b3d7cfb4b0ee4807bfc98a15330eef"},
		{Z: "d3b747a1d1584a0fc5aefcd4dd8ef9c3", L: 40, Info: "03697296e42a6fdbdb24b3ec", Expected: "2c4363597d42f9f8736e8050b4a6dd033d7ddac6f7211c4810ef74aff01f101d885767d7ae6f1d7f"},
		{Z: "119559a2c0a8888e9c95b9989a460d97", L: 48, Info: "03697296e42a6fdbdb24b3ec", Expected: "97922585f69adf484930cf22b8378c797694438502fa47e2f19f0fee97ca11451f3bc81a20c1d74964c63ab2d5df1985"},
		{Z: "807f375266988df5d0ae878efac424fa", L: 56, Info: "03697296e42a6fdbdb24b3ec", Expected: "ba78ef8ab720fc583bb64581917634fca230876cc344e46b44fe61f3bdab556ee753743b78db4b16c0fcd8f987aebad15d0b7b13a10f6819"},
		{Z: "f7906f870b256753b5bc3ef408e47e9b", L: 64, Info: "03697296e42a6fdbdb24b3ec", Expected: "96bee2ae234f98c285aa970bd54c2e2891febf734bad58a91dc7a97490b6b05fe539f2156ae3acd2e661eced0d59084fda340cd1ba3daa7ca2a550d7b1c19462"},
	},
	"HMAC-SHA512": {
		{Z: "73b6e2ede34aae5680e2289e611ffc3a", L: 16, Salt: "28df8439747d5a9b502e0838ca6999b2", Info: "232941631fc04dd82f727a51", Expected: "b0d36cd7d6b23b48ca6f89901bb784ec"},
		{Z: "88683a2f53e3ca3c8b2d781cfe313a5b", L: 16, Salt: "ee97ec4f4b10375edab4ea17794ddcda", Info: "a02625bbff1637af9e5893fd", Expected: "f1a19424a30b3e3f1fbb61a4dc6a9549"},
		{Z: "c69b03db3975033eade2c07a60e08a00", L: 16, Salt: "233641150609686b0f753f81dbb19364", Info: "52a1388a0a54783a089a1ca5", Expected: "df64c46d70a96bee9b9a04a55c3baf25"},
		{Z: "a1d5c8ec5325b5fc26e09cd4121214b8", L: 16, Salt: "0e5997ffb6719f4e7276530252f2e17e", Info: "e0681af7ac0a3d39e2d404d5", Expected: "a882d741597636d574e12e8dd789c402"},
		{Z: "f5754e55adf26a77c6dc2f580bb7f53c", L: 16, Salt: "d8171d0db40a41bf328fe13945f0b97d", Info: "96c79d827e65a13115022b1d", Expected: "81a1404f7d5dd18bae1999fc9a709c41"},
		{Z: "9583359b100b71da1761baee9a553455", L: 16, Salt: "01c8c3b5544c8a8493bb12d030b9ceac", Info: "ad6b4a587575349594781d5c", Expected: "2562b1fb20c77c808b45e3c9c4edd308"},
		{Z: "65c16395870e049fdd8bca67a1b8562d", L: 16, Salt: "ca1bbccadb43a3ce731cd6190c14c209", Info: "e9bf333d1cecea7880c486d9", Expected: "7fd02cbbc372c963e3bc8b478ccc03d7"},
		{Z: "a8a02adb7abbdeeec9d0687742aed4a3", L: 16, Salt: "aa2a9395b475da502457876c48a63b8d", Info: "d4a40c3a8a7ae6555b690191", Expected: "c2e02ca821fbdaa8ab271f4c4abda00a"},
		{Z: "6df86766b8c3bf3590865cc5bba8e103", L: 16, Salt: "d1090dc9fde98b92ce87dd7517efe436", Info: "fa233ee3cd56eb25b38c025e", Expected: "31592cde40945fdb3a7be1b539ae7359"},
		{Z: "7f2871673fc49a76c03c323c6098a1de", L: 16, Salt: "1cc841290118bbae09c768a1c3d79319", Info: "aec457334061d13baf4e1ea8", Expected: "8360581a67b1bb983de140b339d36144"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 2, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295d"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 4, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 6, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 8, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe2"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 10, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 12, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 14, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 16, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 18, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 20, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e3"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 22, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 24, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 26, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 28, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 30, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 32, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a3"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 34, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 36, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e606"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 38, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 40, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 42, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc36"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 44, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 46, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 48, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 50, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093bf75"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 52, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093bf752eea"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 54, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093bf752eea4299"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 56, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093bf752eea4299472e"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 58, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093bf752eea4299472eeb4c"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 60, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093bf752eea4299472eeb4c16c0"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 62, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093bf752eea4299472eeb4c16c065a6"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 64, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093bf752eea4299472eeb4c16c065a6768c"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 66, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093bf752eea4299472eeb4c16c065a6768c93ee"},
		{Z: "8e5cd5f6ae558ffa04cda2fad94dd616", L: 68, Salt: "6ed93b6fe5b3502bb42b4c0fcb133662", Info: "4a433018e51c09bbd61326bb", Expected: "295dfbeb54ec0fe24ece32f5b87c853e699a62e39d9c9ee6ee78f8b9a0ee50a36a82e6062c95ed53bc366700e2d0e093bf752eea4299472eeb4c16c065a6768c93ee8711"},
		{Z: "2ede", L: 16, Salt: "32d92e066f23154ccdae4fa4e6553d2a", Info: "aa633081242afe8b9ca03019", Expected: "4e0568b6911a9b2143f343036aaae127"},
		{Z: "571aaf3e", L: 16, Salt: "32d92e066f23154ccdae4fa4e6553d2a", Info: "aa633081242afe8b9ca03019", Expected: "0e20e1981383eb18f8589fb051c10e75"},
		{Z: "ac7726fc64a3", L: 16, Salt: "32d92e066f23154ccdae4fa4e6553d2a", Info: "aa633081242afe8b9ca03019", Expected: "6cf17f0ac3401206bdcdbaf3a98329e5"},
		{Z: "f9dbb5d0cb68f7e7", L: 16, Salt: "32d92e066f23154ccdae4fa4e6553d2a", Info: "aa633081242afe8b9ca03019", Expected: "1b92a04405fae67ebb6f5a846603e55a"},
		{Z: "8960a4a6b5c87be811aa", L: 16, Salt: "32d92e066f23154ccdae4fa4e6553d2a", Info: "aa633081242afe8b9ca03019", Expected: "c9f15b4d98492774653829acac101a50"},
		{Z: "6ba6ab70fc3329a6d64bacdb", L: 16, Salt: "32d92e066f23154ccdae4fa4e6553d2a", Info: "aa633081242afe8b9ca03019", Expected: "519687b51dce24368294dfe85286cdba"},
		{Z: "f0436cffe85a4882dfac0f4707f7", L: 16, Salt: "32d92e066f23154ccdae4fa4e6553d2a", Info: "aa633081242afe8b9ca03019", Expected: "aa1e838821283b428462578465722a3f"},
		{Z: "b4887363540d7e29e08e3f83bc126bd1", L: 16, Salt: "32d92e066f23154ccdae4fa4e6553d2a", Info: "aa633081242afe8b9ca03019", Expected: "2f7b8d2be10f9776af19ec6db6c68554"},
		{Z: "29c4807337be94a16188fcb10091da90", L: 16, Salt: "52bfe7b0cfa2ae91b88e289ddcd45422", Info: "c65d", Expected: "f23d4dc5d4422ac945e75f024f1d685b"},
		{Z: "29c4807337be94a16188fcb10091da90", L: 16, Salt: "52bfe7b0cfa2ae91b88e289ddcd45422", Info: "abd01670", Expected: "ba8a07b93cf88e8acd1e1f8b22fc3370"},
		{Z: "29c4807337be94a16188fcb10091da90", L: 16, Salt: "52bfe7b0cfa2ae91b88e289ddcd45422", Info: "77b2d073e526", Expected: "41d7da586aa4234c59db540e173bf483"},
		{Z: "29c4807337be94a16188fcb10091da90", L: 16, Salt: "52bfe7b0cfa2ae91b88e289ddcd45422", Info: "0b6bbe8dbf5e9521", Expected: "f3b069219b9db97be85a67292235bdcc"},
		{Z: "29c4807337be94a16188fcb10091da90", L: 16, Salt: "52bfe7b0cfa2ae91b88e289ddcd45422", Info: "47e5ad575d77af763928", Expected: "7f7cfdf12571083a8a199bd976062c64"},
		{Z: "29c4807337be94a16188fcb10091da90", L: 16, Salt: "52bfe7b0cfa2ae91b88e289ddcd45422", Info: "9fe51eee8e78431e0d2f52de", Expected: "041d7957934999e6042a368e3000de79"},
		{Z: "29c4807337be94a16188fcb10091da90", L: 16, Salt: "52bfe7b0cfa2ae91b88e289ddcd45422", Info: "f548bc348202ced205461660ce95", Expected: "e1f8161531786fea044438078fe92fbc"},
		{Z: "29c4807337be94a16188fcb10091da90", L: 16, Salt: "52bfe7b0cfa2ae91b88e289ddcd45422", Info: "a6b968ebecb15f36c82566a1c2346ac2", Expected: "48c1b1673ac41cc7173922f9d5043a3a"},
		{Z: "881afc1b8cc27ab2afac3c7f82b1dd02", L: 16, Salt: "eb49", Info: "54211735d84fff0bb11a9d65", Expected: "6bba31a37a39bbd36492116afb6c82de"},
		{Z: "881afc1b8cc27ab2afac3c7f82b1dd02", L: 16, Salt: "c64e3f96", Info: "54211735d84fff0bb11a9d65", Expected: "f76015cb8cb9c652f067531385e21bb8"},
		{Z: "881afc1b8cc27ab2afac3c7f82b1dd02", L: 16, Salt: "40045301a1e5", Info: "54211735d84fff0bb11a9d65", Expected: "c191af01bde79b0f3d96b5310de935b1"},
		{Z: "881afc1b8cc27ab2afac3c7f82b1dd02", L: 16, Salt: "78e0bb7d7a13736e", Info: "54211735d84fff0bb11a9d65", Expected: "251aeb19be741fbbc4db25beb8dda74d"},
		{Z: "881afc1b8cc27ab2afac3c7f82b1dd02", L: 16, Salt: "0c60d50d3e5c63e91c27", Info: "54211735d84fff0bb11a9d65", Expected: "10dc68d60710d1131c369e1b78c16391"},
		{Z: "881afc1b8cc27ab2afac3c7f82b1dd02", L: 16, Salt: "e586f92b542e7e6fde15121b", Info: "54211735d84fff0bb11a9d65", Expected: "ec61a168a3b2d2d5473cb91f37125a13"},
		{Z: "881afc1b8cc27ab2afac3c7f82b1dd02", L: 16, Salt: "1ab12a395aa1035493c1e5255aac", Info: "54211735d84fff0bb11a9d65", Expected: "8093db84887de54ffba00a842616ce1a"},
		{Z: "881afc1b8cc27ab2afac3c7f82b1dd02", L: 16, Salt: "9f66508c2c492016ef5d88e88cc6f835", Info: "54211735d84fff0bb11a9d65", Expected: "8f0b757834d1fe682718d3e2c0dfe8e0"},
		{Z: "b6c80821db0265bb256a9f9b31b7f10e", L: 8, Salt: "9d090204723f0d674fd9a2a2b5183af7", Info: "", Expected: "23c20ccc20448172"},
		{Z: "f8492561e9c95082c2e019e1fab40565", L: 16, Salt: "9d090204723f0d674fd9a2a2b5183af7", Info: "", Expected: "ad2df36048d60aa5d5a99eaa7b002f85"},
		{Z: "fa850fa9ed0a9fa2a039d10190a85a71", L: 24, Salt: "9d090204723f0d674fd9a2a2b5183af7", Info: "", Expected: "5e5501003185cd482a56136e1ae168c4d19013294300fdc7"},
		{Z: "7da2fe5129a455a8223ac92763200fdf", L: 32, Salt: "9d090204723f0d674fd9a2a2b5183af7", Info: "", Expected: "dc3783d7b7b91d2c6fcfa96e5201b3127ee4465a69451f83fa6335b91a85fb53"},
		{Z: "59f21b28eaa252b945e50797e354c88e", L: 40, Salt: "9d090204723f0d674fd9a2a2b5183af7", Info: "", Expected: "5432bec29feaa500d4f7e5a0b9fdf8b7512e09732eee12722b8b123dd21dca51e0d3cdc30f8a10aa"},
		{Z: "c9520b6fdd8cfb698af4282efce8463b", L: 48, Salt: "9d090204723f0d674fd9a2a2b5183af7", Info: "", Expected: "0ee477232957623dea7b6269b97c84df1260463501b2df12f3b43e51b5c519a82269f8c80d4a735ee57fdff45864d044"},
		{Z: "0f743ee045d6d56ab63fca0ba77ed292", L: 56, Salt: "9d090204723f0d674fd9a2a2b5183af7", Info: "", Expected: "59d9171a104062fbd7f993514f858ae0c63086d25e0fbae93e7cafa79b40fb55cdff2a7b4239f0b5b3fbcab834a0a645459babd8a0688d34"},
		{Z: "1d5525df721d6cf54b13f5a471b18e06", L: 64, Salt: "9d090204723f0d674fd9a2a2b5183af7", Info: "", Expected: "6518e70e71c7525994d39772134a974549f903a25e91e6065da4f46c272b0334820088173995daded29f83c3c7b665dd4bd837c1e5187d368120f7b1b8bbedbb"},
		{Z: "92608b120cdab9f7ec014792f68d8c34", L: 8, Info: "a80b9061879365b1669c87a8", Expected: "07cf98ecda991607"},
		{Z: "d67a13de49d1a1dcbe31927e822eaa63", L: 16, Info: "a80b9061879365b1669c87a8", Expected: "102ae742602458a22aff536792dcd3bc"},
		{Z: "deb71366ec24678cec6a1ab184f71aa2", L: 24, Info: "a80b9061879365b1669c87a8", Expected: "f27246e7811ae25e3a6484431263132dadc55f244f2f7316"},
		{Z: "245083f97809dd2ade6bc5a4cd5aff44", L: 32, Info: "a80b9061879365b1669c87a8", Expected: "84e145dc9dedd26699e1924e67e6cf9316c4a58f78fd33638347190777bf92b8"},
		{Z: "bae8c765b877b8e0b5c09c58def9f5e7", L: 40, Info: "a80b9061879365b1669c87a8", Expected: "31eb2f6e846d723e3127b15ec8edff07e81a25ced6013ddec93b0e06971bbc9b9e2f34e47f3dafd1"},
		{Z: "b715fbc6a3dc600ac7849a219ee37afe", L: 48, Info: "a80b9061879365b1669c87a8", Expected: "d9784dfbea1fd813e60130cc4b602fbf66028bd03eeecc7829d4078f0187affd4cc2b19355ccf9b6f72371a462ee831c"},
		{Z: "170b2e8b8975a0b3fa59cdf62c7bb824", L: 56, Info: "a80b9061879365b1669c87a8", Expected: "1b3d90247ef018f4b93c60772cd0a7af6533cf42dc2caf7dfa5c3b4347c804864c4713e985ccc70c953a9caaaa17e8ae28da5023a5beb208"},
		{Z: "abb7d7554c0de41cada5826a1f79d76f", L: 64, Info: "a80b9061879365b1669c87a8", Expected: "71e29fff69198eca92f5180bcb281fbdaf409ec7c99ca704b1f56e782d3c4db10cb4158e6634d793a46c13bffb6bdb71a01101936ea9b20f7dbe302558b1356c"},
	},
}
