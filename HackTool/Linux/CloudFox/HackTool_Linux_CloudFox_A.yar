
rule HackTool_Linux_CloudFox_A{
	meta:
		description = "HackTool:Linux/CloudFox.A,SIGNATURE_TYPE_ELFHSTR_EXT,16 00 16 00 0b 00 00 "
		
	strings :
		$a_01_0 = {61 77 73 2f 61 77 73 2d 73 64 6b 2d 67 6f } //2 aws/aws-sdk-go
		$a_01_1 = {6d 69 74 63 68 65 6c 6c 68 2f 6d 61 70 73 74 72 75 63 74 75 72 65 } //2 mitchellh/mapstructure
		$a_01_2 = {62 69 73 68 6f 70 66 6f 78 2f 6b 6e 6f 77 6e 61 77 73 61 63 63 6f 75 6e 74 73 6c 6f 6f 6b 75 70 } //2 bishopfox/knownawsaccountslookup
		$a_01_3 = {73 65 72 76 69 63 65 2f 65 6c 61 73 74 69 63 6c 6f 61 64 62 61 6c 61 6e 63 69 6e 67 76 32 } //2 service/elasticloadbalancingv2
		$a_01_4 = {62 73 6f 6e 63 6f 72 65 2e 73 6f 72 74 61 62 6c 65 53 74 72 69 6e 67 } //2 bsoncore.sortableString
		$a_01_5 = {61 65 61 64 63 72 79 70 74 65 72 2e 53 32 41 41 45 41 44 43 72 79 70 74 65 72 } //2 aeadcrypter.S2AAEADCrypter
		$a_01_6 = {67 69 74 68 75 62 2e 63 6f 6d 2f 42 69 73 68 6f 70 46 6f 78 2f 63 6c 6f 75 64 66 6f 78 2f 69 6e 74 65 72 6e 61 6c } //2 github.com/BishopFox/cloudfox/internal
		$a_01_7 = {7a 73 74 64 2e 62 65 74 74 65 72 46 61 73 74 45 6e 63 6f 64 65 72 44 69 63 74 } //2 zstd.betterFastEncoderDict
		$a_01_8 = {67 6f 2e 6f 70 65 6e 63 65 6e 73 75 73 2e 69 6f 2f 73 74 61 74 73 2f 76 69 65 77 2e 72 65 67 69 73 74 65 72 56 69 65 77 52 65 71 } //2 go.opencensus.io/stats/view.registerViewReq
		$a_01_9 = {73 32 61 2d 67 6f 2f 69 6e 74 65 72 6e 61 6c 2f 74 6f 6b 65 6e 6d 61 6e 61 67 65 72 2e 73 69 6e 67 6c 65 54 6f 6b 65 6e 41 63 63 65 73 73 54 6f 6b 65 6e 4d 61 6e 61 67 65 72 } //2 s2a-go/internal/tokenmanager.singleTokenAccessTokenManager
		$a_01_10 = {61 77 73 73 65 72 76 69 63 65 6d 61 70 } //2 awsservicemap
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2) >=22
 
}