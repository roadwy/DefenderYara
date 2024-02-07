
rule VirTool_Win32_CeeInject_GN{
	meta:
		description = "VirTool:Win32/CeeInject.GN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d9 c1 d8 c1 d8 c1 d8 e1 d8 e1 d8 c1 d8 c1 d8 c1 d8 c1 dd da d9 c1 dc 1d 90 01 02 40 00 df e0 9e 76 df 90 00 } //01 00 
		$a_03_1 = {8b de 8a 88 90 01 02 40 00 8b 45 fc 99 f7 fb 32 0d 90 01 02 40 00 8b 5d 08 88 8c 05 58 eb ff ff 8a 8c 1d 58 eb ff ff 8d 84 1d 58 eb ff ff 80 f9 f2 77 04 fe c9 88 08 90 00 } //00 00 
		$a_00_2 = {78 } //eb 00  x
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_GN_2{
	meta:
		description = "VirTool:Win32/CeeInject.GN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff ff 01 6a 0c 68 90 01 03 00 e8 90 01 02 ff ff 83 c4 08 c6 45 90 01 01 90 01 01 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 6a 0e 8d 4d 90 1b 02 51 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {00 6a 08 8d 45 90 01 01 50 e8 90 01 02 ff ff 90 09 23 00 c6 45 90 1b 00 90 01 01 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 00 } //01 00 
		$a_03_2 = {ff f3 a5 66 a5 6a 1a 8d 8d 90 01 02 ff ff 51 e8 90 01 02 ff ff 90 09 05 00 8d bd 90 1b 00 ff 90 00 } //01 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}