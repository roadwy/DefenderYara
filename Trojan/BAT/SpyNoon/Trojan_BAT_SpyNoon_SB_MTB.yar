
rule Trojan_BAT_SpyNoon_SB_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SB!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 08 17 58 0c } //10
		$a_01_1 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}