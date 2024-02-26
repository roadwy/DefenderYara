
rule Trojan_BAT_DarkComet_ADO_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 8e 69 18 5a 03 8e 69 58 0a 2b 35 02 06 02 8e 69 5d 91 03 06 03 8e 69 5d 91 61 02 06 17 58 02 8e 69 5d 91 59 20 00 01 00 00 58 0b 07 20 00 01 00 00 5d d2 0c 02 06 02 8e 69 5d 08 9c 06 15 58 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DarkComet_ADO_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 16 13 05 16 0c 06 74 90 01 01 00 00 01 08 1f 64 d6 17 d6 8d 90 01 01 00 00 01 28 90 01 01 00 00 0a 74 90 01 01 00 00 1b 0a 07 06 11 05 1f 64 6f 90 01 01 00 00 0a 13 06 11 06 16 2e 0e 11 05 11 06 d6 13 05 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}