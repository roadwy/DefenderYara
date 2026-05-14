
rule Trojan_BAT_DarkComet_ADD_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 16 06 a2 11 06 17 1a 8c ?? 00 00 01 a2 11 06 18 06 8e b7 1a da 8c ?? 00 00 01 a2 11 06 13 07 11 07 14 14 19 8d ?? 00 00 01 13 08 11 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADD_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 0a 11 05 11 09 91 13 04 11 05 11 09 11 05 06 91 9c 11 05 06 11 04 9c 11 05 11 09 91 11 05 06 91 d6 20 00 01 00 00 5d 0c 03 50 11 0a 03 50 11 0a 91 11 05 08 91 61 9c 11 0a 17 d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}