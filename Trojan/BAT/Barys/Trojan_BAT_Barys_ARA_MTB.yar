
rule Trojan_BAT_Barys_ARA_MTB{
	meta:
		description = "Trojan:BAT/Barys.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 } //02 00 
		$a_01_1 = {6f 48 55 45 4b 2e 72 65 73 6f 75 72 63 65 73 } //02 00  oHUEK.resources
		$a_01_2 = {79 6b 6d 42 46 2e 72 65 73 6f 75 72 63 65 73 } //00 00  ykmBF.resources
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Barys_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Barys.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 11 17 11 19 58 06 11 19 58 47 11 05 11 19 11 05 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d2 52 00 11 19 17 58 13 19 11 19 11 10 8e 69 fe 04 13 1a 11 1a 2d cc 90 00 } //02 00 
		$a_01_1 = {3c 53 48 49 45 4c 44 3e } //00 00  <SHIELD>
	condition:
		any of ($a_*)
 
}