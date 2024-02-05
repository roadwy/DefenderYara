
rule VirTool_Win32_VBInject_TC{
	meta:
		description = "VirTool:Win32/VBInject.TC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {66 0f b6 0c 08 8b 95 90 01 02 ff ff 8b 45 90 01 01 66 33 0c 50 90 00 } //01 00 
		$a_03_1 = {03 d1 0f 80 90 01 04 52 50 e8 90 02 15 8b 8d 90 01 02 ff ff b8 01 00 00 00 03 c1 0f 80 90 01 04 89 85 90 01 02 ff ff e9 90 00 } //01 00 
		$a_00_2 = {55 00 44 00 5f 00 74 00 6f 00 6f 00 6c 00 73 00 5f 00 40 00 } //01 00 
		$a_03_3 = {3b c7 7d 0b 6a 28 68 90 01 04 56 50 ff d3 8b 0e 8d 55 90 01 01 52 68 90 01 04 68 90 01 04 56 ff 51 90 01 01 3b c7 7d 0b 90 00 } //01 00 
		$a_03_4 = {ff 51 44 81 bd 90 01 04 50 45 00 00 0f 85 90 01 04 8b 55 90 01 01 8b 06 8d 8d 90 01 04 83 c2 34 51 6a 04 0f 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}