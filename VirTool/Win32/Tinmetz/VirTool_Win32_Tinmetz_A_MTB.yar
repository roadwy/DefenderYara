
rule VirTool_Win32_Tinmetz_A_MTB{
	meta:
		description = "VirTool:Win32/Tinmetz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 e4 f8 81 ec ac 01 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 a8 01 00 00 53 8b 1d ?? ?? ?? ?? 8d ?? ?? ?? 56 8b 35 ?? ?? ?? ?? 57 50 68 02 02 00 00 33 ff ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 6a 01 ff 15 } //1
		$a_03_1 = {6a 00 6a 04 68 ?? ?? ?? ?? 53 ff 15 60 20 40 00 a1 ?? ?? ?? ?? 6a 40 68 00 10 00 00 83 c0 05 50 6a 00 ff 15 00 20 40 00 a3 ?? ?? ?? ?? c6 00 bf 89 58 01 8b 35 ?? ?? ?? ?? 85 f6 ?? ?? 0f 1f 44 00 00 6a 00 83 c0 05 56 03 c7 50 53 ff 15 ?? ?? ?? ?? 03 f8 2b f0 a1 ?? ?? ?? ?? ?? ?? 8b 8c 24 b4 01 00 00 5f 5e 5b 33 cc e8 ?? ?? ?? ?? 8b e5 5d c3 } //1
		$a_03_2 = {8b 40 0c 53 8b 00 8b 00 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 c4 04 50 ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 6a 00 89 4c 24 18 b9 02 00 00 00 6a 01 51 66 a3 ?? ?? ?? ?? 66 89 4c 24 1c 66 89 44 24 1e ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}