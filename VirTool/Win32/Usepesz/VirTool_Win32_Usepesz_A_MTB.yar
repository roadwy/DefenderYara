
rule VirTool_Win32_Usepesz_A_MTB{
	meta:
		description = "VirTool:Win32/Usepesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 51 83 ec 54 [0-26] c7 44 24 20 00 00 00 00 ?? ?? ?? 89 44 24 1c c7 44 24 18 00 00 00 00 c7 44 24 14 02 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 8b 45 f4 89 44 24 04 c7 04 24 01 00 00 80 ?? ?? ?? ?? ?? 83 ec 24 89 45 e8 83 7d e8 00 } //1
		$a_03_1 = {8b 45 ec 89 04 24 ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 e0 89 54 24 14 8b 55 ec 89 54 24 10 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 8b 55 f0 89 54 24 04 89 04 24 ?? ?? ?? ?? ?? 83 ec 18 89 45 e4 83 7d e4 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}