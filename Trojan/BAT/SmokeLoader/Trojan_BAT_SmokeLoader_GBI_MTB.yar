
rule Trojan_BAT_SmokeLoader_GBI_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.GBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {11 04 17 58 13 04 11 04 20 00 01 00 00 5d 13 04 11 06 11 0a 11 04 94 58 13 06 11 06 20 00 01 00 00 5d 13 06 11 0a 11 04 94 13 08 11 0a 11 04 11 0a 11 06 94 9e 11 0a 11 06 11 08 9e 11 0a 11 0a 11 04 94 11 0a 11 06 94 58 20 00 01 00 00 5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 95 } //01 00 
		$a_01_1 = {50 72 6f 67 72 61 6d 5f 50 6c 61 79 69 6e 67 } //00 00  Program_Playing
	condition:
		any of ($a_*)
 
}