
rule Trojan_BAT_DarkComet_AKT_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0a 2b 55 06 17 58 20 00 01 00 00 5d 0a 11 07 11 08 06 91 58 20 00 01 00 00 5d 13 07 11 08 06 91 0b 11 08 06 11 08 11 07 91 9c 11 08 11 07 07 9c 11 08 06 91 11 08 11 07 91 58 20 00 01 00 00 5d 13 05 02 50 11 0a 02 50 11 0a 91 11 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}