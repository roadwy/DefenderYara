
rule Trojan_WinNT_AdwindAC_YA_MTB{
	meta:
		description = "Trojan:WinNT/AdwindAC.YA!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 74 76 62 63 74 65 } //01 00 
		$a_01_1 = {63 62 65 71 67 71 62 67 6e 70 6d 63 } //01 00 
		$a_01_2 = {69 69 7a 6b 79 } //01 00 
		$a_01_3 = {6e 7d 7f 6b 6a 7d 4e 4a 54 4a 42 6b 65 2a } //01 00 
		$a_01_4 = {7d 69 69 5c 4a } //01 00 
		$a_01_5 = {53 65 63 72 65 74 4b 65 79 53 70 65 63 } //01 00 
		$a_01_6 = {4f 4b 5e 4a 4b } //00 00 
		$a_00_7 = {5d 04 00 00 } //33 22 
	condition:
		any of ($a_*)
 
}