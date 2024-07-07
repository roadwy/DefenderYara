
rule Trojan_BAT_SpyNoon_KAB_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f 90 01 01 00 00 0a 17 59 fe 01 2c 04 16 0d 2b 04 09 17 58 0d 11 04 17 58 13 04 11 04 02 8e 69 fe 04 2d cd 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_SpyNoon_KAB_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 06 11 0a 11 06 8e 69 5d 11 06 11 0a 11 06 8e 69 5d 91 11 07 11 0a 1f 16 5d 6f 90 01 02 00 0a 61 28 90 01 02 00 0a 11 06 11 0a 17 58 11 06 8e 69 5d 91 28 90 01 02 00 0a 59 20 90 01 02 00 00 58 20 90 01 02 00 00 5d 28 90 01 02 00 0a 9c 00 11 0a 15 58 13 0a 11 0a 16 fe 04 16 fe 01 13 0b 11 0b 2d a1 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}