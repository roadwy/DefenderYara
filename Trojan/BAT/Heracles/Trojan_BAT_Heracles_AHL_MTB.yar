
rule Trojan_BAT_Heracles_AHL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 4e 00 00 01 28 90 01 03 06 74 01 00 00 1b 28 90 01 03 06 17 2d 03 26 de 06 0a 2b fb 26 de d0 06 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Heracles_AHL_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 8b 00 00 70 28 90 01 03 06 1b 2d 1c 26 28 90 01 03 0a 06 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 90 00 } //1
		$a_01_1 = {02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Heracles_AHL_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 33 11 08 11 09 9a 13 0a 11 0a 73 90 01 01 01 00 0a 13 0b 00 11 0b 6f 90 01 01 01 00 0a 00 de 10 25 28 90 01 01 00 00 0a 13 0c 00 28 90 01 01 00 00 0a de 00 00 00 11 09 17 d6 13 09 11 09 11 08 8e 69 90 00 } //2
		$a_01_1 = {43 00 68 00 65 00 63 00 6b 00 58 00 53 00 45 00 4f 00 } //1 CheckXSEO
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}