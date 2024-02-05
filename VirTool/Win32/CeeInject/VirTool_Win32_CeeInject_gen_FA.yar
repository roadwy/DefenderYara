
rule VirTool_Win32_CeeInject_gen_FA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 f8 09 c0 75 04 83 c8 } //01 00 
		$a_01_1 = {c1 c6 02 81 ee } //01 00 
		$a_01_2 = {d1 ce 81 ee } //01 00 
		$a_01_3 = {c1 ee 06 03 } //01 00 
		$a_01_4 = {32 c4 fe c8 02 c4 32 c4 2a c4 fe c8 04 a9 d0 c8 aa d0 c4 } //00 00 
	condition:
		any of ($a_*)
 
}