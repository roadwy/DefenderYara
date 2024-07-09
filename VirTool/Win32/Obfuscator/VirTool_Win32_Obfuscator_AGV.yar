
rule VirTool_Win32_Obfuscator_AGV{
	meta:
		description = "VirTool:Win32/Obfuscator.AGV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5f 43 6f 72 45 78 65 4d 61 69 6e } //1 _CorExeMain
		$a_03_1 = {fe 09 00 00 fe 0e 00 00 fe 0c 00 00 20 90 90 ec 29 d8 66 65 20 e2 6f 19 66 61 20 77 83 30 be 61 65 65 3b ?? ?? ?? ?? fe 0c 00 00 20 8a 78 b6 93 66 66 20 7f 87 49 6c 61 65 65 65 59 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}