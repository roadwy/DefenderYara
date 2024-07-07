
rule Trojan_BAT_DarkComet_AGFE_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AGFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 25 17 58 0a 02 7b 02 00 00 04 07 6f 90 01 03 0a 08 91 9c 08 17 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}