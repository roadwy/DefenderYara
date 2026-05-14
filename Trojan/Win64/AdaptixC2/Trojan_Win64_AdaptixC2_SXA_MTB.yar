
rule Trojan_Win64_AdaptixC2_SXA_MTB{
	meta:
		description = "Trojan:Win64/AdaptixC2.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 ?? 83 7c 24 ?? 10 7d 26 e8 ?? ?? ?? ?? 33 d2 b9 00 01 00 00 f7 f1 8b c2 48 63 4c 24 } //20
		$a_03_1 = {8b c1 88 44 24 ?? 0f b6 44 24 ?? d0 e0 88 44 24 ?? 48 8b 84 24 ?? ?? ?? ?? 48 8b 00 0f b6 4c 24 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}