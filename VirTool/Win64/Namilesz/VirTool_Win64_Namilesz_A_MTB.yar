
rule VirTool_Win64_Namilesz_A_MTB{
	meta:
		description = "VirTool:Win64/Namilesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {4d 8b 77 08 48 8b 5b 08 4d 8b 7c 24 08 48 89 44 24 28 83 64 24 20 00 4c 89 f1 48 89 da 4d 89 f8 41 b9 09 00 00 00 ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 48 8b 8c 24 70 01 00 00 ?? ?? ?? ?? ?? 85 c0 } //1
		$a_03_1 = {41 b8 11 00 00 00 [0-20] 48 83 a4 24 b8 00 00 00 00 83 a4 24 b4 00 00 00 00 31 c9 31 d2 45 31 c0 45 31 c9 ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 48 89 c6 31 c9 31 d2 45 31 c0 45 31 c9 ?? ?? ?? ?? ?? 48 89 c5 31 c9 31 d2 45 31 c0 45 31 c9 ?? ?? ?? ?? ?? 48 89 c7 } //1
		$a_03_2 = {b9 ed b0 da 1e ?? ?? ?? ?? ?? 49 89 c7 ?? ?? ?? ?? ?? ?? ?? ?? 48 c7 06 08 00 00 00 83 a4 24 60 0c 00 00 00 48 89 c1 ba e2 fa de 58 ?? ?? ?? ?? ?? 49 89 c6 4c 89 f9 ba 88 28 e9 50 ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 4c 89 b4 24 e0 01 00 00 48 89 5c 24 38 ?? ?? ?? ?? ?? ?? ?? ?? 4c 89 64 24 28 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 7c 24 20 c7 44 24 30 80 00 00 00 89 c1 41 b8 05 00 00 00 49 c7 c1 ff ff ff ff ?? ?? ?? ?? ?? 41 c6 06 c3 4c 89 f9 ba 88 28 e9 50 } //1
		$a_03_3 = {41 b8 04 00 00 00 ?? ?? ?? ?? ?? 4c 8b a4 24 a0 00 00 00 ?? ?? ?? ?? ?? 4d 8b 14 24 48 89 74 24 28 89 44 24 20 4c 89 e1 ba 00 04 00 00 45 31 c0 41 89 d9 ?? ?? ?? ?? 49 8b 04 24 4c 89 e1 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b b4 24 f0 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 49 83 20 00 48 89 f1 ba 0e 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}