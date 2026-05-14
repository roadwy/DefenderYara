
rule Trojan_Win64_Alevaul_GTV_MTB{
	meta:
		description = "Trojan:Win64/Alevaul.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 48 5d db c7 45 ?? 3b a4 7a 4c c7 45 ?? 5b d7 ea b8 c7 45 ?? 59 d7 3f a2 c7 45 ?? 7b 55 61 c3 } //5
		$a_01_1 = {66 44 0b c0 66 44 89 01 0f b7 42 02 0f b7 c8 66 c1 e8 0a 66 83 e1 1c 66 83 e0 0f 66 c1 e1 02 66 0b c8 66 41 89 49 02 0f b7 42 04 0f b7 c8 66 c1 e8 0a 66 83 e1 1c 66 83 e0 0f 66 c1 e1 02 66 0b c8 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}