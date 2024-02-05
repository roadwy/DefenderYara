
rule VirTool_Win32_Obfuscator_JH{
	meta:
		description = "VirTool:Win32/Obfuscator.JH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 54 6a 40 53 68 cc 1b 00 00 57 89 4d fc 89 55 c0 89 4d c4 89 45 cc 89 75 d0 89 7d d8 e8 } //01 00 
		$a_01_1 = {30 03 46 89 75 ec 3b 75 2c 72 b8 } //00 00 
	condition:
		any of ($a_*)
 
}