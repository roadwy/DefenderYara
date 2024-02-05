
rule Trojan_BAT_Seraph_AANZ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AANZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {09 72 01 00 00 70 28 90 01 01 00 00 0a 72 33 00 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 04 14 13 05 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_3 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //00 00 
	condition:
		any of ($a_*)
 
}