
rule Trojan_BAT_Formbook_RDE_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 32 34 36 65 61 35 61 2d 61 30 31 38 2d 34 36 32 33 2d 39 62 62 65 2d 34 65 32 33 35 62 39 61 61 31 64 30 } //1 f246ea5a-a018-4623-9bbe-4e235b9aa1d0
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
		$a_01_4 = {42 48 68 48 55 69 75 } //1 BHhHUiu
		$a_01_5 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 } //1 CryptoObfuscator_Output
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}