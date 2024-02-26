
rule Trojan_BAT_SpyNoon_AMBG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 0b 08 11 09 91 61 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 11 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpyNoon_AMBG_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0a 02 18 5d 3a 90 01 01 00 00 00 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 38 90 01 01 00 00 00 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 06 28 90 01 01 00 00 0a 38 90 00 } //01 00 
		$a_03_1 = {0a 0b 02 28 90 01 01 00 00 0a 0c 08 17 3b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}