
rule Trojan_BAT_DarkComet_NE_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 28 13 00 00 0a 0b 07 6f 14 00 00 0a 0c 06 20 60 af d9 8d 28 01 00 00 06 0d 12 03 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}