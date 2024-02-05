
rule VirTool_Win32_Obfuscator_XO{
	meta:
		description = "VirTool:Win32/Obfuscator.XO,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {c8 10 00 00 83 7c 24 1c 01 74 } //01 00 
		$a_02_1 = {81 fa 6c 6c 33 32 74 90 01 01 81 fa 6c 6f 72 65 74 90 00 } //01 00 
		$a_00_2 = {89 e5 e8 00 00 00 00 5a } //00 00 
	condition:
		any of ($a_*)
 
}