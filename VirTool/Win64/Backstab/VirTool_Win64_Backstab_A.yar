
rule VirTool_Win64_Backstab_A{
	meta:
		description = "VirTool:Win64/Backstab.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 89 5d a0 ff ?? ?? ?? 00 00 48 8b c8 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? 00 00 85 c0 ?? ?? 48 8b 4d a0 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 ?? ?? ?? ?? ?? 89 5c 24 74 ?? ?? ?? c7 45 ?? 04 00 00 00 ff ?? ?? ?? 00 00 } //1
		$a_03_1 = {48 89 5c 24 28 ?? ?? ?? ?? 41 b9 10 00 00 00 48 89 5c 24 20 33 d2 ff ?? ?? ?? 00 00 48 8b 4d ?? 85 c0 } //1
		$a_03_2 = {bf 01 00 00 00 89 7c 24 40 ff ?? ?? ?? 00 00 33 d2 b9 00 10 00 00 44 8b c0 89 44 24 44 44 8b f0 ff ?? ?? ?? 00 00 49 3b c4 } //1
		$a_03_3 = {48 33 c4 48 89 85 30 08 00 00 0f 10 ?? ?? ?? ?? 00 8b 05 0b 42 00 00 4c 8b e2 48 89 54 24 78 44 8b f9 89 4c 24 60 33 d2 41 b8 f4 01 00 00 0f 29 85 10 04 00 00 ?? ?? ?? ?? ?? ?? ?? 89 85 20 04 00 00 e8 ?? ?? 00 00 33 db } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}