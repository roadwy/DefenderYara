
rule Trojan_Win64_Lazy_KKC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.KKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 f7 d9 48 89 54 24 70 4c 8b e2 44 8a 24 01 44 88 20 49 03 c3 44 89 a5 68 0f 00 00 83 c7 ff 75 } //20
		$a_01_1 = {48 8b fa 41 c1 e2 08 44 0b d0 0f b6 41 02 41 c1 e2 08 44 0b d0 0f b6 41 01 41 c1 e2 08 b9 00 10 00 00 44 0b d0 48 8b 44 24 28 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}