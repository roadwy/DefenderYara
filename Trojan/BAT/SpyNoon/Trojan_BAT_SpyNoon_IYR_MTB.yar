
rule Trojan_BAT_SpyNoon_IYR_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.IYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 73 a9 00 00 0a 0b 28 90 01 03 06 0c 16 0d 2b 41 00 16 13 04 2b 27 00 08 09 11 04 28 90 01 03 06 13 08 11 08 28 90 01 03 0a 13 09 07 09 11 09 d2 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 0a 11 0a 2d ce 06 17 58 0a 00 09 17 58 0d 09 20 00 52 00 00 fe 04 13 0b 11 0b 2d b1 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}