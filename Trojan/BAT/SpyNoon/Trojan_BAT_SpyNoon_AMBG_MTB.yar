
rule Trojan_BAT_SpyNoon_AMBG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0b 08 11 09 91 61 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 11 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_SpyNoon_AMBG_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 02 18 5d 3a ?? 00 00 00 72 ?? 00 00 70 28 ?? 00 00 0a 38 ?? 00 00 00 72 ?? 00 00 70 28 ?? 00 00 0a 06 28 ?? 00 00 0a 38 } //1
		$a_03_1 = {0a 0b 02 28 ?? 00 00 0a 0c 08 17 3b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}