
rule Trojan_BAT_Remcos_PZ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6f 09 00 00 0a 16 28 05 00 00 0a 26 28 90 01 03 06 28 07 00 00 0a 7e 90 01 03 04 28 90 01 03 06 28 07 00 00 0a 28 0e 00 00 0a 2a 90 09 14 00 28 90 01 03 06 7e 90 01 03 04 7e 90 01 03 04 7e 90 01 03 04 90 00 } //01 00 
		$a_01_1 = {25 0a 07 31 01 2a 02 06 28 10 00 00 0a 03 06 03 6f 0f 00 00 0a 5d 17 d6 28 10 00 00 0a da 28 11 00 00 0a 28 12 00 00 0a 28 13 00 00 0a 74 0b 00 00 01 06 17 d6 2b c9 } //00 00 
	condition:
		any of ($a_*)
 
}