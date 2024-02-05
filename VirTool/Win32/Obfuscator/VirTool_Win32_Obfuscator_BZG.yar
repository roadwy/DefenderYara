
rule VirTool_Win32_Obfuscator_BZG{
	meta:
		description = "VirTool:Win32/Obfuscator.BZG,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0c 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 44 24 04 28 de 73 75 } //01 00 
		$a_01_1 = {c7 44 24 04 be 35 84 36 } //01 00 
		$a_01_2 = {c7 44 24 04 d1 8a 31 46 } //01 00 
		$a_01_3 = {c7 44 24 04 61 d1 d4 9e } //01 00 
		$a_01_4 = {c7 44 24 04 a6 b8 bf 9a } //0a 00 
		$a_01_5 = {c1 c8 19 0f be c9 31 c8 83 c2 01 0f b6 0a 84 c9 75 ee } //00 00 
		$a_00_6 = {5d 04 00 } //00 4d 
	condition:
		any of ($a_*)
 
}