
rule Trojan_BAT_Mallox_ND_MTB{
	meta:
		description = "Trojan:BAT/Mallox.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {19 91 6e 1d 2c 4c 1f 38 62 2b 5e 18 91 6e 1f 30 62 58 1d 2c 0c 2b 58 17 91 16 2d f1 } //5
		$a_01_1 = {62 58 2b 46 1b 91 6e 19 2c 0c 1f 18 62 58 2b 3d 1a 91 1f 10 62 6a 58 2b 37 1d 91 18 2c f4 1e 62 6a 58 06 1c 91 6e 58 } //5
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {53 79 73 74 65 6d 2e 4e 65 74 2e 48 74 74 70 } //1 System.Net.Http
		$a_81_4 = {48 74 74 70 43 6c 69 65 6e 74 } //1 HttpClient
		$a_81_5 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
		$a_81_6 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=15
 
}