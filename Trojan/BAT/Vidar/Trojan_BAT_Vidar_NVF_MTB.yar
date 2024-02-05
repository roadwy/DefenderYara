
rule Trojan_BAT_Vidar_NVF_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 7b 16 00 00 04 17 6f 90 01 01 00 00 0a 00 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 26 2a 90 00 } //01 00 
		$a_01_1 = {39 61 6d 6f 75 73 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Vidar_NVF_MTB_2{
	meta:
		description = "Trojan:BAT/Vidar.NVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 37 00 00 70 6f 90 01 02 00 0a 28 90 01 02 00 0a 0a 2b 00 06 2a 90 00 } //01 00 
		$a_01_1 = {66 61 33 61 31 36 38 34 33 33 36 30 31 37 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}