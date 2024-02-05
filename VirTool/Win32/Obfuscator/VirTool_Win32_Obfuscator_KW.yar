
rule VirTool_Win32_Obfuscator_KW{
	meta:
		description = "VirTool:Win32/Obfuscator.KW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 83 38 6a 0f 85 } //01 00 
		$a_01_1 = {80 38 c2 0f 85 } //01 00 
		$a_01_2 = {83 fa 0f 0f 83 } //00 00 
	condition:
		any of ($a_*)
 
}