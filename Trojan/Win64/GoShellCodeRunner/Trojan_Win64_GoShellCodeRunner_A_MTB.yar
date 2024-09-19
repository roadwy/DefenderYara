
rule Trojan_Win64_GoShellCodeRunner_A_MTB{
	meta:
		description = "Trojan:Win64/GoShellCodeRunner.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {48 8b 4c 24 28 48 89 48 08 48 c7 40 10 00 30 00 00 48 c7 40 18 40 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c3 bf 04 00 00 00 48 89 d0 48 89 f9 } //1
		$a_00_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_81_2 = {65 6e 63 6f 64 69 6e 67 2f 68 65 78 2e 44 65 63 6f 64 65 53 74 72 69 6e 67 } //1 encoding/hex.DecodeString
		$a_81_3 = {65 6e 63 6f 64 69 6e 67 2f 62 61 73 65 36 34 2e 28 2a 45 6e 63 6f 64 69 6e 67 29 2e 44 65 63 6f 64 65 } //1 encoding/base64.(*Encoding).Decode
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}