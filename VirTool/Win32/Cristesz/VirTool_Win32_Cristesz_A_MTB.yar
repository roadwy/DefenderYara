
rule VirTool_Win32_Cristesz_A_MTB{
	meta:
		description = "VirTool:Win32/Cristesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {50 56 6a 00 6a 20 6a 00 6a 00 6a 00 ?? ?? ?? ?? ?? ?? ?? 50 6a 00 ff ?? ?? ?? ?? ?? 85 c0 } //1
		$a_03_1 = {56 6a 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 6a 04 68 00 30 00 00 68 00 ?? ?? ?? 6a 00 56 ff ?? ?? ?? ?? ?? 89 44 24 78 85 c0 } //1
		$a_03_2 = {8b 4c 24 78 ?? ?? ?? ?? 50 c1 e1 0a 68 00 04 00 00 ?? ?? ?? ?? ?? ?? 50 8b 44 24 74 03 c1 50 56 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 81 7c 24 74 00 04 00 00 ?? ?? ?? ?? ?? ?? 8b 44 24 78 } //1
		$a_03_3 = {50 6a 00 6a 00 57 6a 00 6a 00 56 ff ?? ?? ?? ?? ?? 8b f8 85 ff } //1
		$a_03_4 = {56 6a 05 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c ff 74 24 68 6a 05 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}