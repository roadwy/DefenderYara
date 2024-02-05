
rule VirTool_Win32_Obfuscator_XP{
	meta:
		description = "VirTool:Win32/Obfuscator.XP,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 04 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {2d 75 34 1f d9 } //05 00 
		$a_01_1 = {33 c9 32 4c 90 03 } //01 00 
		$a_01_2 = {8b 80 a4 00 00 00 } //01 00 
		$a_01_3 = {8b 90 80 00 00 00 } //01 00 
		$a_01_4 = {8b 90 88 00 00 00 } //01 00 
		$a_01_5 = {64 ff 35 30 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}