
rule Trojan_BAT_Heracles_AMMB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {26 2b 01 26 01 11 0f 28 90 01 01 00 00 06 11 0d 09 06 28 90 01 01 00 00 06 16 28 90 01 01 00 00 06 13 05 90 00 } //01 00 
		$a_01_1 = {11 05 1b 5d 13 04 11 05 1b 5b 0c 16 0a 1f 09 13 06 2b a0 } //02 00 
		$a_01_2 = {b4 e8 3d 35 06 6b de ca c2 5f 47 37 e6 44 02 a5 e9 24 4e c8 81 8c 4b 04 9e 7d 15 dc 63 c6 ef 38 84 } //00 00 
	condition:
		any of ($a_*)
 
}