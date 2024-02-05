
rule Trojan_BAT_njRAT_MBCE_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 03 08 17 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0b 00 08 17 58 b5 0c 08 11 04 13 05 11 05 31 d1 90 00 } //01 00 
		$a_01_1 = {61 38 39 31 2d 36 31 31 36 32 33 32 62 33 66 36 35 } //00 00 
	condition:
		any of ($a_*)
 
}