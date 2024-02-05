
rule VirTool_Win32_CeeInject_GO{
	meta:
		description = "VirTool:Win32/CeeInject.GO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {89 45 fc ff 35 90 01 04 ff 75 fc e8 90 01 04 89 45 f0 ff 75 f8 ff 75 f4 ff 35 90 01 04 6a 00 ff 55 f0 89 45 fc 68 90 01 04 68 90 01 02 00 00 68 90 01 04 ff 75 fc e8 90 01 04 68 90 01 04 ff 75 fc c3 90 09 0a 00 68 90 01 04 e8 90 00 } //01 00 
		$a_03_1 = {0f 9f c1 d3 f8 90 09 0b 00 8b 90 01 01 33 90 01 03 33 c9 83 90 00 } //01 00 
		$a_03_2 = {0f 9d c1 2b c1 90 0a 0c 00 33 90 01 01 90 02 02 83 90 00 } //01 00 
		$a_00_3 = {78 c8 00 } //00 01 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_GO_2{
	meta:
		description = "VirTool:Win32/CeeInject.GO,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {b1 71 f6 e9 8a c8 8a c3 02 05 90 01 02 00 10 80 c2 4b 80 3d c2 90 01 02 10 21 88 0d c1 90 01 02 10 88 15 90 01 02 00 10 a2 c7 90 01 02 10 c6 05 90 01 02 00 10 7c 7c 1a 90 00 } //01 00 
		$a_03_1 = {68 45 42 0f 00 6a 00 ff d7 8b 95 90 01 02 ff ff 6a 00 8d 8d 90 01 02 ff ff 51 8b d8 0f b6 05 90 01 03 10 68 46 42 0f 00 56 04 71 90 00 } //01 00 
		$a_01_2 = {83 fe 39 0f 95 c0 0b c3 33 c9 83 fa 3c 0f 94 c1 c1 e6 64 03 c1 85 f6 74 07 } //01 00 
		$a_03_3 = {69 c9 9c 37 00 00 03 ca 8d 54 90 01 02 52 6a 40 89 0d 90 01 03 00 8b 0d 90 01 03 00 68 04 30 00 00 51 c7 44 90 01 02 40 00 00 00 ff d0 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}