
rule VirTool_Win64_Oveloadesz_A_MTB{
	meta:
		description = "VirTool:Win64/Oveloadesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 68 4c ?? ?? ?? ?? 48 89 74 24 28 41 b9 10 00 00 00 33 d2 48 89 44 24 74 48 8b cb c7 44 24 70 01 00 00 00 c7 44 24 7c 02 00 00 00 48 89 74 24 20 ff 15 ?? ?? ?? ?? 85 } //1
		$a_03_1 = {48 33 c4 48 89 84 24 80 00 00 00 33 f6 48 89 74 24 40 ff 15 ?? ?? ?? ?? 48 8b c8 4c ?? ?? ?? ?? 8d ?? ?? ff 15 ?? ?? ?? ?? 48 8b 5c 24 40 4c ?? ?? ?? ?? 48 8d 15 } //1
		$a_03_2 = {4c 8b c0 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 45 33 c9 48 89 74 24 30 89 74 24 28 48 8d ?? ?? ?? ?? ?? ba 00 00 00 40 48 89 7c 24 48 89 74 24 50 45 ?? ?? ?? c7 44 24 20 03 00 00 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}