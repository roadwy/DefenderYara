
rule VirTool_Win32_Obfuscator_ABV{
	meta:
		description = "VirTool:Win32/Obfuscator.ABV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e8 02 33 c2 c1 e8 0a 33 c2 33 c1 } //01 00 
		$a_03_1 = {41 8b c1 99 bb 90 01 02 00 00 f7 fb 81 fa 90 01 02 00 00 75 02 33 c9 45 8b c5 99 bb 90 01 02 00 00 90 01 02 81 fa 90 01 02 00 00 75 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}