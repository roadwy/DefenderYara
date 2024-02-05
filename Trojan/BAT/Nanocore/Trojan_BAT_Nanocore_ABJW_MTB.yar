
rule Trojan_BAT_Nanocore_ABJW_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 06 06 11 06 9a 1f 10 28 90 01 03 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de 90 00 } //01 00 
		$a_01_1 = {57 00 46 00 41 00 5f 00 59 00 61 00 63 00 68 00 74 00 5f 00 44 00 69 00 63 00 65 00 2e 00 44 00 53 00 53 00 44 00 57 00 45 00 } //00 00 
	condition:
		any of ($a_*)
 
}