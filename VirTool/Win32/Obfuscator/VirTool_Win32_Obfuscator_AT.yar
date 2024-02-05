
rule VirTool_Win32_Obfuscator_AT{
	meta:
		description = "VirTool:Win32/Obfuscator.AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 58 58 58 58 6b db 90 01 01 ff d4 50 8b 40 90 01 01 05 90 01 04 0f 85 90 01 04 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}