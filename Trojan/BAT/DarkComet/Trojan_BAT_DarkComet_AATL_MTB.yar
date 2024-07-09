
rule Trojan_BAT_DarkComet_AATL_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AATL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 14 11 06 11 04 02 7b ?? 00 00 04 11 04 91 9c 11 04 17 58 13 04 11 04 11 06 8e 69 fe 04 13 08 11 08 2d de } //3
		$a_03_1 = {16 13 04 2b 1f 02 7b ?? 00 00 04 02 7b ?? 00 00 04 8e 69 11 04 59 17 59 11 06 11 04 91 9c 11 04 17 58 13 04 11 04 11 06 8e 69 fe 04 13 08 11 08 2d d3 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}