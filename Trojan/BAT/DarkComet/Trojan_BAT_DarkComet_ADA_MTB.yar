
rule Trojan_BAT_DarkComet_ADA_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 3a 09 11 07 02 11 07 91 07 61 08 11 04 91 61 9c 08 28 ?? ?? ?? 0a 00 11 04 08 8e 69 17 da fe 01 16 fe 01 13 08 11 08 2d 05 16 13 04 2b 07 00 11 04 17 d6 13 04 11 07 17 d6 13 07 11 07 11 06 fe 02 16 fe 01 13 08 11 08 2d b7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}