
rule VirTool_Win32_CeeInject_gen_HF{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 90 09 03 00 c7 45 90 00 } //01 00 
		$a_01_1 = {8b 9d a4 00 00 00 83 c3 08 } //01 00 
		$a_03_2 = {8b 5d 34 03 5d 28 53 8d ac 24 90 01 04 58 89 85 b0 00 00 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}