
rule VirTool_Win32_CeeInject_XW_bit{
	meta:
		description = "VirTool:Win32/CeeInject.XW!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 04 0f 99 bb 90 01 04 f7 fb 8b 45 90 01 01 8a 04 02 30 01 ff 4d 90 01 01 ff 45 90 01 01 41 81 7d 90 01 01 00 04 00 00 7f 05 39 75 90 01 01 75 d8 90 00 } //02 00 
		$a_03_1 = {03 c1 99 b9 90 01 04 f7 f9 8b 45 90 01 01 8a 0c 02 8b 45 90 01 01 30 08 ff 45 90 01 01 8b 4d 90 01 01 40 3b 4d 90 01 01 89 45 90 01 01 7c d9 90 00 } //01 00 
		$a_03_2 = {6a 40 03 df 8b 43 50 8b 4b 34 68 00 30 00 00 50 51 ff 75 90 01 01 89 4d 90 01 01 8b 53 28 89 55 90 01 01 ff 55 90 00 } //01 00 
		$a_03_3 = {8d 14 39 89 10 83 c1 28 83 c0 04 3b 4d 90 01 01 7c f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}