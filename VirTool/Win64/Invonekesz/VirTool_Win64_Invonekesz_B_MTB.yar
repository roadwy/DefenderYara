
rule VirTool_Win64_Invonekesz_B_MTB{
	meta:
		description = "VirTool:Win64/Invonekesz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 47 30 1f 00 10 00 80 3d [0-23] 41 b8 08 00 00 00 48 89 f9 ?? ?? ?? ?? ?? 31 c0 48 3b 07 ?? ?? ?? ?? ?? ?? 48 8b 5c 24 38 48 8b 7c 24 40 48 89 d9 ?? ?? ?? ?? ?? 48 85 c0 ?? ?? 48 89 d9 ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 49 89 c6 } //1
		$a_03_1 = {48 89 d9 48 89 fa ?? ?? ?? ?? ?? 80 3d [0-23] 41 b8 09 00 00 00 48 89 f9 ?? ?? ?? ?? ?? 31 c0 48 3b 07 [0-11] 49 8b 5e 08 49 8b 7e 10 48 89 d9 ?? ?? ?? ?? ?? 49 89 c4 ?? ?? ?? ?? ?? ?? ?? 41 b8 0e 00 00 00 4c 89 f1 ?? ?? ?? ?? ?? 31 c0 49 3b 06 ?? ?? ?? ?? ?? ?? 4c 8b 7c 24 38 4c 8b 74 24 40 4c 89 e1 4c 89 fa } //1
		$a_03_2 = {4c 89 e8 48 f7 d8 ?? ?? ?? ?? ?? ?? 48 b8 48 ?? ?? 74 ?? 48 ?? ?? 48 89 84 24 f0 01 00 00 c6 84 24 f8 01 00 00 74 [0-15] 41 b8 08 00 00 00 48 89 f9 ?? ?? ?? ?? ?? 31 c0 48 3b 07 48 8b 9c 24 20 01 00 00 ?? ?? ?? ?? ?? ?? 48 8b 8c 24 48 03 00 00 48 8b 84 24 50 03 00 00 48 89 44 24 40 48 89 8c 24 18 01 00 00 ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? 4c 8b a4 24 08 01 00 00 [0-14] 48 89 c7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}