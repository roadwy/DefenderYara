
rule VirTool_Win64_Injdll_A{
	meta:
		description = "VirTool:Win64/Injdll.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 48 83 3d ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 4c ?? ?? ?? ?? ?? ?? 33 d2 b9 02 00 00 00 ff } //1
		$a_03_1 = {48 89 44 24 30 48 8b 4c 24 30 ff ?? ?? ?? ?? ?? c7 44 24 28 01 00 00 00 48 c7 44 24 20 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 4c ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 33 c9 ff ?? ?? ?? ?? ?? 48 8b 4c 24 30 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}