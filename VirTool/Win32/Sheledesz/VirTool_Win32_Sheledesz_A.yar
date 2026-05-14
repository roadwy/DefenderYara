
rule VirTool_Win32_Sheledesz_A{
	meta:
		description = "VirTool:Win32/Sheledesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 57 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 68 50 31 40 00 c7 44 24 2c 00 00 00 00 c7 44 24 30 00 00 00 00 c7 44 24 38 00 00 00 00 c7 44 24 3c 00 00 00 00 c7 44 24 28 ?? ?? ?? ?? ff } //1
		$a_03_1 = {8b 74 24 10 33 c9 33 d2 85 f6 ?? ?? 8a 44 0c 0c 30 04 17 ?? ?? ?? 42 83 f8 03 1b c9 23 c8 3b d6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}