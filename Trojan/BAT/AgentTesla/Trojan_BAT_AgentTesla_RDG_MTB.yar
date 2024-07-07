
rule Trojan_BAT_AgentTesla_RDG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {49 6d 61 67 65 54 72 61 63 65 72 } //1 ImageTracer
		$a_01_1 = {38 34 65 65 32 39 33 65 2d 62 39 33 38 2d 34 35 31 32 2d 38 61 33 39 2d 38 36 66 66 63 30 30 65 64 32 36 37 } //1 84ee293e-b938-4512-8a39-86ffc00ed267
		$a_01_2 = {4e 65 74 5a 61 64 31 } //1 NetZad1
		$a_01_3 = {48 00 79 00 76 00 65 00 73 00 } //1 Hyves
		$a_01_4 = {50 4c 4f 4b 4d 34 32 } //1 PLOKM42
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_01_7 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
		$a_01_8 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_01_9 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}