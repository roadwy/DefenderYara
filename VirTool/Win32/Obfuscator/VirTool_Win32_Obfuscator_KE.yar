
rule VirTool_Win32_Obfuscator_KE{
	meta:
		description = "VirTool:Win32/Obfuscator.KE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c0 85 c0 0f 84 } //01 00 
		$a_01_1 = {8b b0 88 00 00 00 8d 54 02 18 89 55 ec } //01 00 
		$a_03_2 = {c7 45 f0 01 00 00 00 90 09 1c 00 c7 45 e0 90 01 01 00 00 00 c7 45 e4 90 01 01 00 00 00 c7 45 e8 90 01 01 00 00 00 c7 45 ec 90 01 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}