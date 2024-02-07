
rule VirTool_Win32_Obfuscator_gen_D{
	meta:
		description = "VirTool:Win32/Obfuscator.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 e0 fc 33 c1 83 c0 90 01 01 83 c0 90 01 01 83 c0 90 02 04 a3 90 01 03 00 c1 c8 18 89 02 83 c2 04 c7 02 02 00 00 00 90 00 } //01 00 
		$a_00_1 = {51 75 65 75 65 55 73 65 72 41 50 43 } //01 00  QueueUserAPC
		$a_02_2 = {8a 26 32 e0 88 26 46 c7 05 90 01 03 00 00 00 00 00 e2 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}