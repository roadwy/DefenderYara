
rule VirTool_Win32_Obfuscator_PL{
	meta:
		description = "VirTool:Win32/Obfuscator.PL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 dc 85 c9 75 90 14 2d 0d 00 00 c0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}