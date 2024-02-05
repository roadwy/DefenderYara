
rule VirTool_Win32_Obfuscator_KP{
	meta:
		description = "VirTool:Win32/Obfuscator.KP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 03 00 00 7d 90 09 06 00 81 3d 90 00 } //01 00 
		$a_03_1 = {f2 36 df 05 7d 90 09 0a 00 90 02 04 81 3d 90 00 } //01 00 
		$a_01_2 = {81 7d 0c 11 11 11 11 75 07 } //01 00 
		$a_01_3 = {a8 e1 02 07 } //00 00 
	condition:
		any of ($a_*)
 
}