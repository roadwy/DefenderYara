
rule VirTool_Win32_CeeInject_gen_HZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff d0 a1 90 01 04 33 f6 56 ff 70 54 53 ff 70 34 ff 35 90 01 04 ff 15 90 00 } //01 00 
		$a_03_1 = {0f b7 48 06 ff 05 90 01 04 39 0d 90 1b 00 7c 90 00 } //01 00 
		$a_03_2 = {8b 48 34 03 48 28 8d 85 90 01 04 50 ff 35 90 01 04 89 8d 90 00 } //01 00 
		$a_03_3 = {ff 70 50 ff 70 34 ff 35 90 01 04 e8 90 01 04 a1 90 01 04 90 02 04 33 f6 56 ff 70 54 53 ff 70 34 90 00 } //01 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}