
rule VirTool_Win64_Invonekesz_C_MTB{
	meta:
		description = "VirTool:Win64/Invonekesz.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 47 30 1f 00 10 00 80 3d [0-23] 41 b8 08 00 00 00 48 89 f9 ?? ?? ?? ?? ?? 31 c0 48 3b 07 ?? ?? ?? ?? ?? ?? 48 8b 5c 24 38 48 8b 7c 24 40 48 89 d9 ?? ?? ?? ?? ?? 48 85 c0 ?? ?? 48 89 d9 ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 49 89 c6 } //1
		$a_03_1 = {48 89 d9 48 89 fa ?? ?? ?? ?? ?? 80 3d [0-23] 41 b8 09 00 00 00 48 89 f9 ?? ?? ?? ?? ?? 31 c0 48 3b 07 [0-11] 49 8b 5e 08 49 8b 7e 10 48 89 d9 ?? ?? ?? ?? ?? 49 89 c4 ?? ?? ?? ?? ?? ?? ?? 41 b8 0e 00 00 00 4c 89 f1 ?? ?? ?? ?? ?? 31 c0 49 3b 06 ?? ?? ?? ?? ?? ?? 4c 8b 7c 24 38 4c 8b 74 24 40 4c 89 e1 4c 89 fa } //1
		$a_03_2 = {48 8b 1e 48 89 d8 48 f7 d8 4c 8b ad 20 0c 00 00 ?? ?? ?? ?? ?? ?? 4d 89 fe 48 b8 48 ?? ?? 74 ?? 48 ?? ?? 48 89 85 c0 0a 00 00 c6 85 c8 0a 00 00 74 [0-14] 6a 08 41 58 48 89 f1 ?? ?? ?? ?? ?? 31 c0 48 3b 06 ?? ?? ?? ?? ?? ?? 48 8b bd 28 04 00 00 48 8b b5 30 04 00 00 48 89 f9 ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 49 89 c7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}