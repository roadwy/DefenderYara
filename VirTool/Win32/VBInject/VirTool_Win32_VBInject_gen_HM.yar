
rule VirTool_Win32_VBInject_gen_HM{
	meta:
		description = "VirTool:Win32/VBInject.gen!HM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 04 81 07 00 01 00 } //01 00 
		$a_01_1 = {58 59 59 59 6a 04 } //01 00 
		$a_03_2 = {03 c8 0f 80 90 01 04 8b 85 90 01 04 8b 55 90 01 01 89 0c 82 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}