
rule VirTool_Win32_Obfuscator_NV{
	meta:
		description = "VirTool:Win32/Obfuscator.NV,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 00 6a 02 8b 90 01 02 ff ff ff 90 01 01 ff 55 90 00 } //01 00 
		$a_00_1 = {6a 00 6a 04 6a 00 6a ff ff } //01 00 
		$a_00_2 = {8a 0c 11 32 8c 85 c8 fb ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_NV_2{
	meta:
		description = "VirTool:Win32/Obfuscator.NV,SIGNATURE_TYPE_PEHSTR,03 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 85 4c f6 ff ff 2e c6 85 4d f6 ff ff 64 c6 85 4e f6 ff ff 65 c6 85 4f f6 ff ff 72 } //01 00 
		$a_01_1 = {ac d2 c8 aa 81 c1 15 cd 5b 07 4a 0b d2 75 f1 } //00 00 
	condition:
		any of ($a_*)
 
}