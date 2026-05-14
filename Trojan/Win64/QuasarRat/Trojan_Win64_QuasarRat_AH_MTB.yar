
rule Trojan_Win64_QuasarRat_AH_MTB{
	meta:
		description = "Trojan:Win64/QuasarRat.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 54 24 30 48 8d 14 82 8b 02 41 0f b6 c9 41 d3 c0 44 33 c0 44 89 02 8b 8d 20 01 00 00 } //30
		$a_03_1 = {8b 4c 24 3c 8b 44 24 38 33 c8 89 4c 24 40 8b 4c 24 34 c1 e1 ?? 8b 44 24 30 33 c1 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}