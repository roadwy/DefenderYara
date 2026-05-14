
rule Trojan_BAT_QuasarRAT_BAC_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b de 0a 08 2c 06 08 ?? ?? 00 00 0a dc 06 16 73 ?? 00 00 0a 0d 07 73 ?? 00 00 0a 13 04 09 11 04 ?? ?? 00 00 0a 11 04 ?? ?? 00 00 0a 13 05 de 20 11 04 2c 07 11 04 ?? ?? 00 00 0a dc } //2
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_QuasarRAT_BAC_MTB_2{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 ?? ?? 00 00 0a 17 73 29 00 00 0a 13 07 11 07 08 16 08 8e 69 ?? ?? 00 00 0a 11 07 ?? ?? 00 00 0a de 0c 11 07 2c 07 11 07 ?? ?? 00 00 0a dc 11 06 ?? ?? 00 00 0a 13 08 de 18 11 06 2c 07 11 06 ?? ?? 00 00 0a dc } //2
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}