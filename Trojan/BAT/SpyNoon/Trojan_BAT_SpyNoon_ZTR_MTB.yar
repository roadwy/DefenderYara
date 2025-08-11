
rule Trojan_BAT_SpyNoon_ZTR_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ZTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 05 06 6f ?? 00 00 0a 0b 23 00 00 00 00 00 80 41 40 23 00 00 00 00 00 00 14 40 28 ?? 00 00 06 58 0c 08 23 33 33 33 33 33 33 e3 3f 5a 0d 12 01 28 ?? 00 00 0a 12 01 } //6
		$a_03_1 = {59 13 09 11 09 19 32 29 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 3b 11 09 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}