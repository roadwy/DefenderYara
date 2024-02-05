
rule Trojan_BAT_Xworm_NEAB_MTB{
	meta:
		description = "Trojan:BAT/Xworm.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 11 01 28 0d 00 00 06 13 03 38 18 00 00 00 28 90 01 01 00 00 0a 11 00 28 13 00 00 06 28 90 01 01 00 00 0a 13 01 90 00 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_2 = {73 65 63 6f 6e 64 6f 70 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}