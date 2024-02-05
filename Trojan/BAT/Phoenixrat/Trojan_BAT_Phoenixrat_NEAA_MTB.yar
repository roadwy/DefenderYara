
rule Trojan_BAT_Phoenixrat_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Phoenixrat.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {26 28 40 00 00 0a 25 26 11 64 28 41 00 00 0a 25 26 6f 42 00 00 0a 25 26 13 67 11 67 14 } //05 00 
		$a_01_1 = {55 73 65 72 73 5c 4c 4f 54 54 45 5c 73 6f 75 72 63 65 } //01 00 
		$a_01_2 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 } //00 00 
	condition:
		any of ($a_*)
 
}