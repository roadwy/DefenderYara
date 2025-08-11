
rule Trojan_Win64_Lazy_KKA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 41 04 b8 00 08 00 00 41 2b c0 c1 e8 05 66 41 03 c0 66 41 89 02 33 c0 eb ?? 44 2b c8 2b d0 41 8b c0 44 89 49 04 c1 e8 05 66 44 2b c0 89 11 66 45 89 02 } //8
		$a_01_1 = {48 8b fa 41 c1 e2 08 44 0b d0 0f b6 41 02 41 c1 e2 08 44 0b d0 0f b6 41 01 41 c1 e2 08 b9 00 10 00 00 44 0b d0 48 8b 44 24 28 44 89 10 44 3b d1 } //7
		$a_01_2 = {41 8b c8 48 8d 7d 00 66 f3 ab 41 0f b7 c2 48 8d 7d a0 41 8b c9 66 f3 ab 41 0f b7 c2 48 8d 7d b8 41 8b c9 66 f3 ab 41 8b c8 41 0f b7 c2 48 8d bd 80 01 00 00 66 f3 ab } //5
		$a_01_3 = {63 72 61 63 6b 6d 79 2e 61 70 70 2f } //10 crackmy.app/
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*7+(#a_01_2  & 1)*5+(#a_01_3  & 1)*10) >=30
 
}