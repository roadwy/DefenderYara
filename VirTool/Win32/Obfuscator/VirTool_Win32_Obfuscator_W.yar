
rule VirTool_Win32_Obfuscator_W{
	meta:
		description = "VirTool:Win32/Obfuscator.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 fc 2d 90 01 04 8d 80 90 01 04 48 66 81 38 50 45 75 f8 8b f8 48 66 81 38 4d 5a 75 f8 8b bf 80 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}