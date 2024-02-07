
rule VirTool_Win32_CeeInject_gen_Q{
	meta:
		description = "VirTool:Win32/CeeInject.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 7d e4 68 58 4d 56 0f 94 c0 eb } //01 00 
		$a_01_1 = {0f 68 48 43 } //02 00  栏䍈
		$a_01_2 = {8a 84 95 f8 fb ff ff 30 06 ff 45 14 8b 45 14 3b 45 10 72 } //03 00 
		$a_01_3 = {75 06 8b 85 d4 fe ff ff 8b 8d c8 fe ff ff 03 c8 } //03 00 
		$a_03_4 = {ff 70 50 ff 70 34 ff 75 90 01 01 ff 15 90 00 } //01 00 
		$a_01_5 = {81 38 50 45 00 00 0f 85 } //02 00 
		$a_03_6 = {99 f7 f9 8b 4d 90 01 01 8a 84 15 90 01 02 ff ff 32 04 31 47 3b 7d 90 01 01 88 06 7c 90 00 } //02 00 
		$a_03_7 = {83 45 08 28 0f b7 41 06 39 45 90 01 01 7c 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}