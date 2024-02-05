
rule VirTool_Win32_CeeInject_gen_BD{
	meta:
		description = "VirTool:Win32/CeeInject.gen!BD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 10 8d 54 24 90 01 01 88 44 24 90 01 01 52 8d 44 24 90 01 01 50 c6 44 24 90 01 01 30 c6 44 24 90 01 01 78 88 4c 24 90 01 01 c6 44 24 90 01 01 00 e8 90 00 } //01 00 
		$a_01_1 = {b8 68 58 4d 56 } //01 00 
		$a_01_2 = {00 64 62 67 68 65 6c 70 2e 64 6c 6c 00 53 62 69 65 44 6c 6c 2e 64 6c 6c 00 } //01 00 
		$a_01_3 = {00 25 73 25 73 25 73 25 73 5b 25 73 5d 7b 7d 25 73 7b 7d } //01 00 
	condition:
		any of ($a_*)
 
}