
rule Trojan_BAT_DarkComet_ADR_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 06 13 05 2b 2d 07 11 05 02 11 05 91 09 61 08 11 04 91 61 b4 9c 11 04 03 6f 90 01 01 00 00 0a 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06 31 cd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}