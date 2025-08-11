
rule Trojan_BAT_SmokeLoader_ZVT_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.ZVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 11 11 18 6f ?? 00 00 0a 13 19 11 08 1f 64 6a 5d 16 6a fe 01 13 25 11 25 39 8c 00 00 00 00 72 75 14 00 70 1d 8d 10 00 00 01 25 16 11 11 } //6
		$a_03_1 = {a2 25 18 12 19 28 ?? 00 00 0a 8c 57 00 00 01 a2 25 19 12 19 28 ?? 00 00 0a 8c 57 00 00 01 a2 25 1a 12 19 28 ?? 00 00 0a 8c 57 00 00 01 a2 25 1b 11 04 8c 51 00 00 01 a2 25 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}