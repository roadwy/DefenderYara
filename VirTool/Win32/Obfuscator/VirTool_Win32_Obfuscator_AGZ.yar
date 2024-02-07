
rule VirTool_Win32_Obfuscator_AGZ{
	meta:
		description = "VirTool:Win32/Obfuscator.AGZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {5f 43 6f 72 45 78 65 4d 61 69 6e } //01 00  _CorExeMain
		$a_01_1 = {20 8b 3c 66 c3 20 ec c9 97 a0 61 20 a1 d1 52 c7 61 20 25 20 07 a1 61 66 66 20 8b 3b 9e 75 61 20 b5 45 e3 ae 61 66 20 78 85 26 21 } //00 00 
	condition:
		any of ($a_*)
 
}