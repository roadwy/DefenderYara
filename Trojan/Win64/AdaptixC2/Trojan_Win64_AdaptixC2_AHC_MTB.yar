
rule Trojan_Win64_AdaptixC2_AHC_MTB{
	meta:
		description = "Trojan:Win64/AdaptixC2.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 d3 ef 8d 48 ?? 41 29 f8 44 31 c1 0f b6 c9 66 89 4c 45 00 48 83 c0 ?? 48 83 f8 ?? 75 } //30
		$a_03_1 = {89 d1 8d 50 [0-04] 31 ca 0f b6 d2 66 41 89 14 ?? 48 83 c0 ?? 48 83 f8 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}