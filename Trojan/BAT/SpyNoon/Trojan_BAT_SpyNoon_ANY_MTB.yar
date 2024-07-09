
rule Trojan_BAT_SpyNoon_ANY_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ANY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 14 2b 71 00 06 19 11 14 5a 6f ?? ?? ?? 0a 13 15 11 15 1f 39 fe 02 13 17 11 17 2c 0d 11 15 1f 41 59 1f 0a 58 d1 13 15 2b 08 11 15 1f 30 59 d1 13 15 06 19 11 14 5a 17 58 6f ?? ?? ?? 0a 13 16 11 16 1f 39 fe 02 13 18 11 18 2c 0d 11 16 1f 41 59 1f 0a 58 d1 13 16 2b 08 11 16 1f 30 59 d1 13 16 08 11 14 1f 10 11 15 5a 11 16 58 d2 9c 00 11 14 17 58 13 14 11 14 07 fe 04 13 19 11 19 2d 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}