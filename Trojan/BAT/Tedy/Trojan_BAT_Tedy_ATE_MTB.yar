
rule Trojan_BAT_Tedy_ATE_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 6b 00 00 70 28 90 01 03 06 0a 28 90 01 03 0a 06 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 0b dd 03 00 00 00 26 de d6 90 00 } //01 00 
		$a_01_1 = {16 0a 02 8e 69 17 59 0b 38 16 00 00 00 02 06 91 0c 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 e6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Tedy_ATE_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 04 12 04 28 90 01 03 0a 0d 1e 8d 90 01 03 01 25 16 72 90 01 03 70 a2 25 17 09 a2 25 18 72 90 01 03 70 a2 25 19 07 a2 25 1a 72 90 01 03 70 a2 25 1b 08 a2 25 1c 72 90 01 03 70 a2 25 1d 06 a2 90 00 } //01 00 
		$a_01_1 = {76 74 5f 74 65 73 74 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 76 74 5f 74 65 73 74 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}