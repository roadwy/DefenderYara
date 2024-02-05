
rule VirTool_Win32_Obfuscator_QI{
	meta:
		description = "VirTool:Win32/Obfuscator.QI,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 42 53 25 f5 1f 17 17 74 15 7b 97 17 17 c6 23 45 4c fa 45 ec 47 23 52 } //01 00 
		$a_01_1 = {ec 53 53 f1 4c 16 25 de fb 25 1e 43 39 4c 16 c6 0f } //01 00 
		$a_01_2 = {c6 3f 19 de fb 19 1e 43 39 37 18 20 41 3f 19 fe 4a ec d6 32 } //01 00 
		$a_01_3 = {64 c6 5b eb 7b 1f 17 17 2b 7b 1b 17 17 b0 3d 1b 1c } //00 00 
	condition:
		any of ($a_*)
 
}