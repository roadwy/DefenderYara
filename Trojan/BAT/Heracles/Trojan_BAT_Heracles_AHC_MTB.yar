
rule Trojan_BAT_Heracles_AHC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 2d 18 08 09 18 5b 06 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 09 18 58 0d 09 07 32 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHC_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0d 00 09 08 16 73 90 01 03 0a 13 04 00 73 90 01 03 0a 13 05 00 11 04 11 05 6f 90 01 03 0a 00 11 05 6f 90 01 03 0a 0a 00 de 14 11 05 14 fe 01 13 07 11 07 2d 08 11 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHC_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0d 2b 61 09 6f 90 01 03 0a 13 04 12 04 28 90 01 03 0a 6f 90 01 03 0a 72 27 00 00 70 16 28 90 01 03 0a 2c 40 72 33 00 00 70 13 05 12 04 28 90 01 03 0a 11 05 16 28 90 01 03 0a 16 31 27 02 6f 90 01 03 06 6f 90 01 03 0a 12 04 28 90 01 03 0a 11 05 72 a9 00 00 70 17 15 16 28 90 00 } //01 00 
		$a_01_1 = {44 00 69 00 73 00 63 00 6f 00 72 00 64 00 3a 00 20 00 44 00 69 00 61 00 72 00 74 00 69 00 6f 00 73 00 23 00 35 00 38 00 35 00 30 00 } //00 00  Discord: Diartios#5850
	condition:
		any of ($a_*)
 
}