
rule Trojan_Win64_CobaltStrike_GNE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 83 e0 01 33 c2 2b c2 48 63 4c 24 48 48 8b 94 24 b8 00 00 00 88 04 0a eb ?? 41 b9 40 00 00 00 41 b8 00 30 00 00 ba a8 c0 5f 00 33 c9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}