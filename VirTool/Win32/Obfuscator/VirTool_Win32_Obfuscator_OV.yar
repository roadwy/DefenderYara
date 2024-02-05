
rule VirTool_Win32_Obfuscator_OV{
	meta:
		description = "VirTool:Win32/Obfuscator.OV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 3e 00 00 90 09 02 00 81 90 05 01 03 c1 2d c7 90 00 } //01 00 
		$a_00_1 = {81 ca 79 79 79 79 } //01 00 
		$a_02_2 = {6a 00 6a 01 90 02 08 ff 55 90 01 01 8b 90 01 01 0c 8b 90 01 05 8d 90 01 06 89 90 01 02 6a 00 8b 90 01 01 08 90 01 01 6a 00 6a 00 ff 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}