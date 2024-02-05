
rule VirTool_Win32_Obfuscator_UX{
	meta:
		description = "VirTool:Win32/Obfuscator.UX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 05 e9 00 00 00 05 b8 0b 00 00 c7 00 } //01 00 
		$a_01_1 = {8a 1e 32 d8 88 1e eb } //01 00 
		$a_01_2 = {59 d1 c0 d1 e0 d1 c0 86 e0 80 e4 fb } //00 00 
	condition:
		any of ($a_*)
 
}