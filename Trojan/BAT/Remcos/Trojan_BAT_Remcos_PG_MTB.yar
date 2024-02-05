
rule Trojan_BAT_Remcos_PG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {70 0b 07 28 90 01 03 0a 74 90 01 03 01 0c 08 72 90 01 03 70 6f 90 01 03 0a 00 08 6f 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a 73 90 00 } //01 00 
		$a_03_1 = {0a 0d 09 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 72 90 01 03 70 6f 90 00 } //01 00 
		$a_03_2 = {0a 14 18 8d 90 01 03 01 25 16 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a a2 25 17 06 28 90 01 03 0a a2 6f 90 01 03 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}