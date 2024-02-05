
rule VirTool_Win32_VBInject_AFD{
	meta:
		description = "VirTool:Win32/VBInject.AFD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {f8 fc 0c 00 c7 45 90 01 01 01 00 00 00 83 65 d4 00 eb 0f 8b 45 d4 03 45 90 01 01 0f 80 90 01 01 16 00 00 89 45 d4 8b 45 d4 3b 45 90 01 01 7f 69 90 09 03 00 c7 45 90 00 } //01 00 
		$a_01_1 = {c7 04 ca 3d 84 f6 3e c7 44 ca 04 68 ae c0 02 8b 50 0c 59 2b 48 14 6a 04 c7 04 ca 3d ee e9 36 c7 44 ca 04 59 4f 39 c1 } //01 00 
		$a_01_2 = {c7 04 ca 54 fc ed fc c7 44 ca 04 66 03 7a 05 8b 50 0c b9 69 01 00 00 2b 48 14 c7 04 ca 38 03 7a 8c c7 44 ca 04 ee cb 23 0f } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}