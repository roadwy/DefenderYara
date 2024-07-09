
rule VirTool_Win64_Hinteloadesz_A_MTB{
	meta:
		description = "VirTool:Win64/Hinteloadesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 b9 00 30 00 00 48 89 7c 24 50 4c 8b c6 c7 44 24 20 40 00 00 00 33 d2 48 8b cb ?? ?? ?? ?? ?? ?? 48 8b f8 48 85 c0 [0-14] 48 8b c8 [0-10] 4c 89 74 24 58 4c 8b ce 45 33 f6 4c 8b c5 48 8b d7 4c 89 74 24 20 48 8b cb ?? ?? ?? ?? ?? ?? 85 c0 } //1
		$a_03_1 = {4c 89 74 24 30 4c 8b cf 44 89 74 24 28 45 33 c0 33 d2 4c 89 74 24 20 48 8b cb ?? ?? ?? ?? ?? ?? 48 83 f8 ff } //1
		$a_03_2 = {48 8b 13 48 8b c8 ?? ?? ?? ?? ?? 48 8b c8 [0-11] 4c 8b 03 33 d2 48 8b c8 ?? ?? ?? ?? ?? ?? 48 8b d8 4c 8b c0 45 85 e4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}