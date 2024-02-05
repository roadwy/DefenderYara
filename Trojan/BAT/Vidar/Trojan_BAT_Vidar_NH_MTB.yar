
rule Trojan_BAT_Vidar_NH_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {25 26 0c 08 20 90 01 02 00 00 28 90 01 02 00 0a 25 26 0d 09 28 90 01 02 00 0a 25 26 13 04 11 04 28 90 01 02 00 0a 90 00 } //01 00 
		$a_01_1 = {49 6e 61 63 74 74 79 72 61 6e 74 73 } //01 00 
		$a_01_2 = {42 77 77 37 34 } //00 00 
	condition:
		any of ($a_*)
 
}