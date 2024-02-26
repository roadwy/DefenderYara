
rule Trojan_BAT_Lazy_ALZ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 0b 72 90 01 01 01 00 70 0c 06 28 90 01 01 00 00 0a 16 fe 01 0d 09 2c 09 00 06 28 90 01 01 00 00 0a 26 00 73 90 01 01 00 00 0a 08 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Lazy_ALZ_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {26 03 1f 10 28 90 01 01 00 00 2b 1f 20 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0c 20 00 00 00 00 38 58 00 00 00 00 38 64 01 00 00 00 73 02 01 00 0a 25 11 04 28 90 01 01 03 00 06 00 25 17 28 90 01 01 03 00 06 00 25 18 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Lazy_ALZ_MTB_3{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 06 07 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 2d 0d 06 07 28 90 01 01 00 00 0a 08 28 90 01 01 00 00 0a de 14 26 72 90 01 01 01 00 70 02 28 90 00 } //01 00 
		$a_01_1 = {0a 0c 08 28 06 00 00 0a 02 6f 07 00 00 0a 6f 08 00 00 0a 08 06 6f 09 00 00 0a 08 08 6f 0a 00 00 0a 08 6f 0b 00 00 0a 6f 0c 00 00 0a 0d 07 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Lazy_ALZ_MTB_4{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 71 00 06 19 11 04 5a 6f 90 01 03 0a 13 05 11 05 1f 39 fe 02 13 07 11 07 2c 0d 11 05 1f 41 59 1f 0a 58 d1 13 05 2b 08 11 05 1f 30 59 d1 13 05 06 19 11 04 5a 17 58 6f 90 01 03 0a 13 06 11 06 1f 39 fe 02 13 08 11 08 2c 0d 11 06 1f 41 59 1f 0a 58 d1 13 06 2b 08 11 06 1f 30 59 d1 13 06 08 11 04 1f 10 11 05 5a 11 06 58 d2 9c 00 11 04 17 58 13 04 11 04 07 fe 04 13 09 11 09 2d 84 90 00 } //01 00 
		$a_01_1 = {50 00 65 00 6c 00 61 00 79 00 6f 00 53 00 4e 00 6f 00 6e 00 6f 00 67 00 72 00 61 00 6d 00 73 00 } //00 00  PelayoSNonograms
	condition:
		any of ($a_*)
 
}