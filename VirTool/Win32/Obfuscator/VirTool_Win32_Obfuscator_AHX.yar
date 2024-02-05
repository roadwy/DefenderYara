
rule VirTool_Win32_Obfuscator_AHX{
	meta:
		description = "VirTool:Win32/Obfuscator.AHX,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 1c 05 00 00 00 00 e9 90 01 02 ff ff 89 f8 8d 3d 90 01 02 4a 00 ab eb 00 eb e1 90 00 } //01 00 
		$a_02_1 = {cc cc cc cc 61 00 00 00 62 00 00 00 63 00 00 00 90 02 0f 6c 64 61 70 5f 63 6f 75 6e 74 5f 76 61 6c 75 65 73 90 02 0f 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}