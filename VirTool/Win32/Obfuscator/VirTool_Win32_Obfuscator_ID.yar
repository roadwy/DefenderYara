
rule VirTool_Win32_Obfuscator_ID{
	meta:
		description = "VirTool:Win32/Obfuscator.ID,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 83 38 6a 0f 85 } //02 00 
		$a_01_1 = {80 38 c2 0f 85 } //01 00 
		$a_03_2 = {31 44 24 04 58 90 09 05 00 b8 90 00 } //01 00 
		$a_01_3 = {81 e9 34 12 00 00 } //01 00 
		$a_01_4 = {81 38 8b ff 8b ff } //00 00 
	condition:
		any of ($a_*)
 
}