
rule VirTool_Win32_Obfuscator_AOV{
	meta:
		description = "VirTool:Win32/Obfuscator.AOV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 ec 5d eb fe } //01 00 
		$a_01_1 = {64 79 6e 63 75 69 2e 64 6c 6c } //01 00  dyncui.dll
		$a_01_2 = {6e 61 6a 75 69 6b 6c 61 2e 70 64 62 } //01 00  najuikla.pdb
		$a_03_3 = {8b 09 81 e9 10 08 00 00 0f 86 90 01 04 e9 90 01 04 c6 05 90 00 } //01 00 
		$a_03_4 = {8b 3f 81 ef 10 08 00 00 0f 86 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}