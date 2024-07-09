
rule Trojan_BAT_AgentTesla_NUH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {57 ff 03 3e 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 ?? 01 00 00 ?? 01 00 00 ?? 04 00 00 ?? 0f 00 00 ?? 09 00 00 3c 00 00 00 ?? 03 00 00 ?? 00 00 00 3d 00 00 00 0e 00 00 00 01 00 00 00 15 } //1
		$a_01_1 = {66 00 69 00 6c 00 65 00 3a 00 2f 00 2f 00 2f 00 00 11 4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 00 33 7b 00 31 00 31 } //1
		$a_80_2 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //System.Security.Cryptography.AesCryptoServiceProvider  1
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_80_4 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //GetDelegateForFunctionPointer  1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}