
rule Trojan_Win64_ShellcodeRunnerGo_A_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunnerGo.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6e 65 74 2f 68 74 74 70 2e 28 2a 43 6c 69 65 6e 74 29 2e 47 65 74 } //1 net/http.(*Client).Get
		$a_81_1 = {65 6e 63 6f 64 69 6e 67 2f 62 61 73 65 36 34 2e 69 6e 69 74 } //1 encoding/base64.init
		$a_81_2 = {63 72 79 70 74 6f 2f 73 75 62 74 6c 65 2e 78 6f 72 42 79 74 65 73 } //1 crypto/subtle.xorBytes
		$a_81_3 = {62 75 69 6c 64 2f 6c 6f 61 64 65 72 2f 74 65 6d 70 2f 74 65 6d 70 2e 67 6f } //1 build/loader/temp/temp.go
		$a_81_4 = {6e 65 74 2f 68 74 74 70 2f 73 6f 63 6b 73 5f 62 75 6e 64 6c 65 2e 67 6f } //1 net/http/socks_bundle.go
		$a_81_5 = {65 6e 63 6f 64 69 6e 67 2f 68 65 78 2f 68 65 78 2e 67 6f } //1 encoding/hex/hex.go
		$a_02_6 = {41 0f b6 44 24 17 89 c1 83 e0 1f 48 89 c3 48 0f ba e8 07 ?? 48 8b b4 24 d8 01 00 00 f6 c1 20 48 0f 44 d8 eb 07 31 db 45 31 e4 31 f6 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_02_6  & 1)*1) >=7
 
}