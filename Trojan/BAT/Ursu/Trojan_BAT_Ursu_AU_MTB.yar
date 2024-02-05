
rule Trojan_BAT_Ursu_AU_MTB{
	meta:
		description = "Trojan:BAT/Ursu.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 2d 15 7e 12 00 00 0a 02 6f 90 01 03 0a 03 04 1a 6f 90 01 03 0a de 24 06 03 6f 90 01 03 0a 04 2e 09 06 03 04 1a 6f 90 01 03 0a de 0a 06 2c 06 06 6f 90 01 03 0a dc de 03 26 de 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Ursu_AU_MTB_2{
	meta:
		description = "Trojan:BAT/Ursu.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 17 12 00 15 6a 16 28 90 01 03 0a 17 8d 0c 00 00 01 0d 09 16 17 9e 09 28 90 01 03 0a 06 72 e9 00 00 70 15 16 28 90 01 03 0a 0b 19 08 90 00 } //01 00 
		$a_01_1 = {62 00 69 00 6e 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}