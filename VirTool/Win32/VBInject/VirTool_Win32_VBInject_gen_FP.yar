
rule VirTool_Win32_VBInject_gen_FP{
	meta:
		description = "VirTool:Win32/VBInject.gen!FP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 04 81 07 00 01 00 } //01 00 
		$a_01_1 = {68 95 e3 35 69 } //01 00 
		$a_03_2 = {66 b9 ff 00 e8 90 01 04 50 e8 90 01 04 8d 45 90 01 01 50 66 b9 d0 00 90 00 } //01 00 
		$a_03_3 = {66 b9 58 00 e8 90 02 30 66 b9 59 00 90 00 } //01 00 
		$a_03_4 = {03 c8 0f 80 90 01 04 8b 85 90 01 04 8b 55 90 01 01 89 0c 82 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}