
rule VirTool_Win32_Obfuscator_IY{
	meta:
		description = "VirTool:Win32/Obfuscator.IY,SIGNATURE_TYPE_PEHSTR_EXT,06 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 83 39 6a 0f 85 } //01 00 
		$a_03_1 = {31 44 24 04 58 90 09 05 00 b8 90 00 } //01 00 
		$a_01_2 = {81 e9 34 12 00 00 } //01 00 
		$a_01_3 = {81 38 8b ff 8b ff } //00 00 
	condition:
		any of ($a_*)
 
}