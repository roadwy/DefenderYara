
rule Trojan_BAT_DarkComet_ADM_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 20 17 19 15 28 90 01 01 00 00 0a 1a 13 0a 17 28 90 01 01 00 00 0a b7 28 90 01 01 00 00 0a 0b 1b 13 0a 17 28 90 01 01 00 00 0a b7 28 90 01 01 00 00 0a 13 05 1c 13 0a 17 28 90 01 01 00 00 0a b7 28 90 01 01 00 00 0a 13 06 1d 13 0a 17 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DarkComet_ADM_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0a 2b 49 72 90 01 01 00 00 70 06 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 0b 07 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 16 9a 0c 08 06 73 90 01 01 00 00 0a 0d 18 17 1c 73 90 00 } //01 00 
		$a_03_1 = {16 0a 2b 1f 7e 90 01 01 00 00 04 06 7e 90 01 01 00 00 04 5d 91 0b 02 06 02 06 91 07 61 28 90 01 01 00 00 0a 9c 06 17 58 0a 06 02 8e 69 32 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}