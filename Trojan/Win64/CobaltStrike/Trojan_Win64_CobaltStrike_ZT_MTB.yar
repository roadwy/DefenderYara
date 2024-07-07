
rule Trojan_Win64_CobaltStrike_ZT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 8c 24 90 01 04 89 81 90 01 04 8b 44 24 90 01 01 c1 e8 10 48 8b 8c 24 90 01 04 48 63 89 90 01 04 48 8b 94 24 90 01 04 48 8b 92 90 01 04 88 04 0a 48 8b 84 24 90 01 04 8b 80 90 01 04 ff c0 48 8b 8c 24 90 01 04 89 81 90 01 04 8b 44 24 90 01 01 c1 e8 08 48 8b 0d 90 01 04 48 63 89 90 01 04 48 8b 15 90 01 04 88 04 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}