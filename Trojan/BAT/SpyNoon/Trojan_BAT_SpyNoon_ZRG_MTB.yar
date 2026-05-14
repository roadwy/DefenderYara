
rule Trojan_BAT_SpyNoon_ZRG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ZRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 23 11 24 6f ?? 00 00 0a 13 26 04 03 6f ?? 00 00 0a 59 13 27 11 27 13 28 11 28 19 fe 02 2c 03 19 13 28 11 28 16 fe 04 2c 03 } //6
		$a_03_1 = {11 2d 16 12 26 28 ?? 00 00 0a 9c 11 2d 17 12 26 28 ?? 00 00 0a 9c 11 2d 18 12 26 28 ?? 00 00 0a 9c 11 28 16 fe 02 2c 0f } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}