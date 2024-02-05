
rule VirTool_Win32_Obfuscator_PV{
	meta:
		description = "VirTool:Win32/Obfuscator.PV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 38 8b ff cc c3 0f 84 } //01 00 
		$a_03_1 = {81 38 33 c0 c2 90 01 01 0f 84 90 00 } //01 00 
		$a_01_2 = {32 4c 90 01 c1 e1 08 32 0c 90 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_PV_2{
	meta:
		description = "VirTool:Win32/Obfuscator.PV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b cc 8d 61 90 01 01 59 90 00 } //01 00 
		$a_03_1 = {8b c4 8d 60 90 01 01 58 90 00 } //01 00 
		$a_01_2 = {81 38 33 c0 c2 08 0f 84 } //01 00 
		$a_03_3 = {81 38 8b ff 90 90 33 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_PV_3{
	meta:
		description = "VirTool:Win32/Obfuscator.PV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 c2 08 0f 90 03 01 01 84 85 90 00 } //01 00 
		$a_03_1 = {8b 45 fc 66 83 78 06 02 0f 90 03 01 01 84 85 90 00 } //01 00 
		$a_01_2 = {bb 90 90 90 90 } //01 00 
		$a_03_3 = {39 58 6f 0f 90 03 01 01 84 85 90 00 } //02 00 
		$a_01_4 = {81 78 05 33 c0 c9 c2 0f } //00 00 
	condition:
		any of ($a_*)
 
}