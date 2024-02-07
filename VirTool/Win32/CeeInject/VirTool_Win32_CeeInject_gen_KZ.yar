
rule VirTool_Win32_CeeInject_gen_KZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 6a 10 50 ff 15 90 01 04 53 6a 2f 68 90 01 04 ff b5 90 01 04 68 fb 00 00 00 ff 15 90 00 } //01 00 
		$a_01_1 = {6a 75 6e 6b 30 00 } //01 00  番歮0
		$a_03_2 = {53 56 57 c6 85 90 01 04 45 c6 85 90 01 04 9b c6 85 90 01 04 fc c6 85 90 01 04 91 c6 85 90 01 04 fc c6 85 90 01 04 6c c6 85 90 01 04 14 c6 85 90 01 04 10 c6 85 90 01 04 10 c6 85 90 01 04 43 c6 85 90 01 04 23 c6 85 90 01 04 cb c6 85 90 01 04 46 c6 85 90 01 04 47 c6 85 90 01 04 d6 c6 85 90 01 04 55 c6 85 90 01 04 c4 c6 85 90 01 04 35 c6 85 90 01 04 d6 c6 85 90 01 04 55 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}