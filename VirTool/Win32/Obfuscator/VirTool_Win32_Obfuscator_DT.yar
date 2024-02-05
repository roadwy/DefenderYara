
rule VirTool_Win32_Obfuscator_DT{
	meta:
		description = "VirTool:Win32/Obfuscator.DT,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 6f 74 65 90 02 04 e8 90 00 } //01 00 
		$a_01_1 = {81 f9 33 32 04 00 e8 } //01 00 
		$a_01_2 = {81 fa 22 01 00 00 e8 } //01 00 
		$a_01_3 = {83 c4 04 f3 a6 e8 } //02 00 
		$a_01_4 = {83 c4 04 30 0f e8 } //01 00 
		$a_01_5 = {8d 80 22 6c 00 00 e8 } //01 00 
		$a_01_6 = {8d 88 00 60 00 00 e8 } //00 00 
	condition:
		any of ($a_*)
 
}