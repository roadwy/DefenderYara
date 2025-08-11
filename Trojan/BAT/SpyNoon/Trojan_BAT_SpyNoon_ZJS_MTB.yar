
rule Trojan_BAT_SpyNoon_ZJS_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ZJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 14 72 d9 3b 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 05 11 04 11 05 28 ?? 01 00 0a 6f ?? 01 00 0a 00 11 0c 11 0b 12 0c 28 ?? 00 00 0a 13 0e 11 0e 2d c4 11 04 6f ?? 01 00 0a 0b 2b 00 07 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}