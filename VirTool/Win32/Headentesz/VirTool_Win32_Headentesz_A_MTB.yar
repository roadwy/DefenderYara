
rule VirTool_Win32_Headentesz_A_MTB{
	meta:
		description = "VirTool:Win32/Headentesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {a1 84 e1 41 00 ?? ?? 83 ec ?? 89 45 e8 c7 04 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 ec ?? a1 0c } //1
		$a_03_1 = {8b 55 f4 89 54 24 ?? c7 44 24 ?? ?? ?? ?? ?? 89 44 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 45 e4 8b 85 } //1
		$a_03_2 = {89 45 ec c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 06 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00 00 a1 ?? ?? ?? ?? ?? ?? 83 ec } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}