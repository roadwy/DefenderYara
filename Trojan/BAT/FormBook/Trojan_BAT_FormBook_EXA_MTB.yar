
rule Trojan_BAT_FormBook_EXA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 08 6f ?? ?? ?? 0a 09 18 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 02 } //1
		$a_01_1 = {24 32 64 31 34 34 36 31 31 2d 36 32 63 35 2d 34 65 62 38 2d 61 30 61 65 2d 38 61 31 36 31 37 39 34 39 64 63 63 } //1 $2d144611-62c5-4eb8-a0ae-8a1617949dcc
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}