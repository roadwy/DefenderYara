
rule VirTool_Win32_VBInject_gen_AR{
	meta:
		description = "VirTool:Win32/VBInject.gen!AR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 04 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 11 00 00 00 8b 85 a8 fe ff ff 03 85 9c fe ff ff 90 02 06 89 85 90 00 } //04 00 
		$a_03_1 = {8b 85 a4 fd ff ff 03 85 98 fd ff ff 90 02 06 89 45 8c 90 00 } //01 00 
		$a_03_2 = {66 81 7d e0 ff 00 75 08 66 c7 45 e0 0e 00 eb 0e 66 8b 45 e0 66 05 01 00 70 90 01 01 66 89 45 e0 90 00 } //01 00 
		$a_03_3 = {66 b9 59 00 e8 90 01 02 ff ff 90 01 25 eb 0b e8 90 01 02 ff ff 89 85 90 01 01 ff ff ff 66 b9 50 00 90 00 } //01 00 
		$a_03_4 = {58 59 59 59 6a 04 90 09 03 00 c7 45 90 00 } //01 00 
		$a_03_5 = {58 59 59 59 90 02 20 c7 45 90 01 01 59 50 00 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}