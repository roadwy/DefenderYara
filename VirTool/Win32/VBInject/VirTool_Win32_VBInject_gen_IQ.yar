
rule VirTool_Win32_VBInject_gen_IQ{
	meta:
		description = "VirTool:Win32/VBInject.gen!IQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 81 b0 00 00 00 } //01 00 
		$a_03_1 = {07 00 01 00 90 09 02 00 c7 90 00 } //01 00 
		$a_03_2 = {8b 42 0c 8b 8d 90 01 04 66 0f b6 14 08 8b 85 90 01 04 8b 4d 90 01 01 66 33 14 41 8b 45 90 01 01 8b 48 0c 8b 85 90 01 04 88 14 01 90 00 } //01 00 
		$a_03_3 = {ff ff 00 30 00 00 c7 85 90 01 02 ff ff 02 00 00 00 90 01 1c c7 85 90 01 02 ff ff 40 00 00 00 c7 85 90 01 02 ff ff 02 00 00 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}