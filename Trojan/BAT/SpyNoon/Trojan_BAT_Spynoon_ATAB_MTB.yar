
rule Trojan_BAT_Spynoon_ATAB_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ATAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 11 05 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 6c 07 28 ?? 00 00 0a 5a 13 07 12 06 28 ?? 00 00 0a 6c 07 23 65 73 2d 38 52 c1 f0 3f 58 28 ?? 00 00 0a 5a 13 08 12 06 28 ?? 00 00 0a 6c 07 23 65 73 2d 38 52 c1 00 40 58 28 ?? 00 00 0a 5a 13 09 11 07 11 07 5a 23 00 00 00 00 20 c0 ef 40 5b 13 0a 11 08 11 08 5a 23 00 00 00 00 20 c0 ef 40 5b 13 0b 11 09 11 09 5a 23 00 00 00 00 20 c0 ef 40 5b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}