
rule Trojan_BAT_Noon_ZZE_MTB{
	meta:
		description = "Trojan:BAT/Noon.ZZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 09 11 05 6f ?? 00 00 0a 13 07 12 07 28 ?? 00 00 0a 20 ?? 00 00 00 fe 04 13 06 11 06 2c 04 07 17 d6 0b 11 05 17 d6 13 05 11 05 11 04 31 d1 } //6
		$a_03_1 = {b7 0f 01 28 ?? 00 00 0a 6c 23 bc 74 93 18 04 56 d6 3f 5a 0f 01 28 ?? 00 00 0a 6c 23 c1 ca a1 45 b6 f3 e5 3f 5a 58 0f 01 28 ?? 00 00 0a 6c 23 1b 2f dd 24 06 81 c5 3f 5a 58 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}