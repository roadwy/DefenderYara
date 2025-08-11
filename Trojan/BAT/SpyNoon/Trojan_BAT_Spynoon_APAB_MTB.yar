
rule Trojan_BAT_Spynoon_APAB_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.APAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 08 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6c 07 28 ?? 00 00 0a 5a 13 04 12 03 28 ?? 00 00 0a 6c 07 23 65 73 2d 38 52 c1 f0 3f 58 28 ?? 00 00 0a 5a 13 05 12 03 28 ?? 00 00 0a 6c 07 23 65 73 2d 38 52 c1 00 40 58 28 ?? 00 00 0a 5a 11 04 11 04 5a 23 00 00 00 00 20 c0 ef 40 5b 13 06 11 05 11 05 5a 23 00 00 00 00 20 c0 ef 40 5b 13 07 25 5a 23 00 00 00 00 20 c0 ef 40 5b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}