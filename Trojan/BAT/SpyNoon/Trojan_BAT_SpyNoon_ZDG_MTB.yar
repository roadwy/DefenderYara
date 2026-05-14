
rule Trojan_BAT_SpyNoon_ZDG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ZDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 04 6f ?? 00 00 0a 13 07 12 07 28 ?? 00 00 0a 13 08 12 07 28 ?? 00 00 0a 13 09 12 07 28 ?? 00 00 0a 13 0a 11 08 28 ?? 00 00 06 13 08 11 09 28 ?? 00 00 06 13 09 11 0a 28 ?? 00 00 06 13 0a 11 08 28 ?? 00 00 06 13 0b 11 09 28 ?? 00 00 06 13 0c 11 0a 28 ?? 00 00 06 13 0d 11 0b 2c 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}