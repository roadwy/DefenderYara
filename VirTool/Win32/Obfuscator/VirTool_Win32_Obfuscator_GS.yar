
rule VirTool_Win32_Obfuscator_GS{
	meta:
		description = "VirTool:Win32/Obfuscator.GS,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {32 c8 30 8a } //4
		$a_01_1 = {81 fa 00 a8 01 00 7d } //4
		$a_01_2 = {b9 07 00 00 00 f3 a5 66 a5 a4 } //4
		$a_01_3 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetWindowsDirectoryA
		$a_01_4 = {53 65 74 42 6b 43 6f 6c 6f 72 } //1 SetBkColor
		$a_01_5 = {53 65 74 42 6b 4d 6f 64 65 } //1 SetBkMode
		$a_01_6 = {47 65 74 42 6b 4d 6f 64 65 } //1 GetBkMode
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=12
 
}