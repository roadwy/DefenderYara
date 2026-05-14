
rule Trojan_Win64_StealC_AH_MTB{
	meta:
		description = "Trojan:Win64/StealC.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 03 c2 41 c1 cb ?? 41 c1 ?? 13 45 33 d9 45 33 d0 41 33 d3 03 d0 33 da 44 03 c3 c1 cb ?? 41 33 d8 } //30
		$a_03_1 = {41 8b c0 41 c1 c8 ?? 2b c3 03 c8 43 8d 04 11 44 33 c1 41 c1 c9 ?? 44 33 c8 41 03 c0 41 c1 c8 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}