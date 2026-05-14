
rule Trojan_Win64_Midie_AH_MTB{
	meta:
		description = "Trojan:Win64/Midie.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {f3 0f e6 c0 66 0f 6e c8 f3 0f e6 c9 41 6b c2 ?? f2 0f 58 c0 41 03 c3 f2 0f 5c c8 f2 0f 59 ca f2 0f 11 4c 24 68 } //30
		$a_03_1 = {23 cf 03 c9 8b 54 83 ?? 48 63 84 24 a0 00 00 00 2b d1 03 94 24 b0 00 00 00 89 54 83 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}