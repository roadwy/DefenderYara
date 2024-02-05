
rule VirTool_Win32_DelfInject_gen_V{
	meta:
		description = "VirTool:Win32/DelfInject.gen!V,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {64 ff 30 64 89 20 52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b 59 5a 33 c0 5a 59 59 64 89 10 } //0a 00 
		$a_00_1 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b 36 8b 04 24 64 89 05 00 00 00 00 83 c4 08 85 db 0f 94 c0 36 8d 65 fc 36 8b 1c 24 36 8b 6c 24 04 83 c4 08 c3 8b 4c 24 0c c7 81 a4 00 00 00 ff ff ff ff 83 81 } //0a 00 
		$a_03_2 = {6a 40 68 00 30 00 00 8b 45 90 01 01 50 8b 45 90 01 01 8b 40 34 50 8b 90 03 06 04 85 90 01 02 ff ff 45 90 01 01 50 90 03 01 01 ff e8 90 00 } //01 00 
		$a_02_3 = {8b 45 fc 33 db 8a 5c 38 ff 33 5d f8 8d 45 ec 8b d3 e8 90 01 04 8b 55 ec 8d 45 f0 e8 90 01 04 47 4e 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}