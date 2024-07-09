
rule Trojan_BAT_SpyNoon_MBCZ_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.MBCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 20 00 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 01 00 0a 13 05 08 11 05 6f ?? 01 00 0a 00 09 18 58 0d 00 09 07 6f ?? 01 00 0a fe 04 13 06 11 06 2d d1 } //1
		$a_01_1 = {72 76 25 00 70 06 72 82 25 00 70 } //1
		$a_01_2 = {72 8c 25 00 70 72 23 04 00 70 } //1
		$a_01_3 = {72 90 25 00 70 72 94 25 00 70 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}