
rule Trojan_BAT_DarkComet_AWI_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 5d 13 0a 11 07 09 94 13 10 11 07 09 11 07 11 0a 94 9e 11 07 11 0a 11 10 9e 11 07 11 07 09 94 11 07 11 0a 94 d6 20 00 01 00 00 5d 94 13 0f 02 11 06 17 da 17 } //00 00 
	condition:
		any of ($a_*)
 
}