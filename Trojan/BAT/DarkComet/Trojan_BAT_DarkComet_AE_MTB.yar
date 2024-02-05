
rule Trojan_BAT_DarkComet_AE_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 07 05 50 6f 90 01 03 0a 26 07 0e 04 6f 90 01 03 0a 26 02 50 28 90 01 03 0a 03 50 28 90 00 } //01 00 
		$a_03_1 = {0a 06 8e b7 1f 0f da 17 d6 8d 90 01 03 01 13 04 06 1f 10 11 04 16 06 8e b7 1f 10 da 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}