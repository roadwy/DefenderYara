
rule Trojan_BAT_Vidar_NDV_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 c8 00 00 0a 0d 08 74 90 01 01 00 00 01 16 73 90 01 01 00 00 0a 73 90 01 01 00 00 0a 13 04 11 04 74 90 01 01 00 00 01 09 75 90 01 01 00 00 01 6f 90 01 01 00 00 0a de 45 18 13 08 90 00 } //01 00 
		$a_01_1 = {7a 35 43 4a 6e 30 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}