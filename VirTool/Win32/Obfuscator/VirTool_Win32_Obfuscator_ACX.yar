
rule VirTool_Win32_Obfuscator_ACX{
	meta:
		description = "VirTool:Win32/Obfuscator.ACX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 fa 72 c6 45 fb 6f c6 45 fc 75 } //01 00 
		$a_01_1 = {8b 4d 10 ff 51 10 89 45 e0 b8 00 00 00 00 b8 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}