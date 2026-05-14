
rule VirTool_Win32_Nedehesz_A{
	meta:
		description = "VirTool:Win32/Nedehesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 e4 f8 81 ec 74 06 00 00 a1 00 50 40 00 33 c4 89 84 24 70 06 00 00 53 56 57 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 64 a1 30 00 00 00 83 c4 04 8b 78 0c 83 c7 14 8b 37 3b f7 } //1
		$a_03_1 = {33 c0 5f 5e 5b 8b 4d fc 33 cd e8 ?? ?? ?? ?? 8b e5 5d c3 8b 4e 10 85 c9 ?? ?? ba } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}