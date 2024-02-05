
rule VirTool_Win32_Alanloader_A{
	meta:
		description = "VirTool:Win32/Alanloader.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 56 51 57 53 52 ba 20 00 00 00 33 ff 8b 75 08 8b 4d 0c 33 db ac 84 c0 90 01 02 c1 cf 13 3c 61 0f 4d da 2a c3 0f b6 c0 03 f8 90 01 02 8b c7 5a 5b 5f 59 5e 8b e5 5d c2 08 00 90 00 } //01 00 
		$a_02_1 = {8b 40 0c 8b 40 14 89 45 fc 89 45 f8 8d 90 01 02 8b 7b 04 85 ff 90 01 02 0f b7 0b 03 f9 fd 33 c0 b0 5c 8b f7 f2 ae fc 90 01 02 83 c7 02 89 7d f4 2b f7 56 57 90 00 } //01 00 
		$a_02_2 = {8b 55 fc 8b 72 20 03 75 08 8b 5d f8 8d 90 01 02 8b 3e 03 7d 08 33 c0 8b f7 b9 12 05 00 00 fc f2 ae 2b fe 4f 57 56 90 00 } //01 00 
		$a_00_3 = {d1 e1 83 c1 68 83 c1 2c 8b f0 51 6a 04 68 00 30 00 00 51 6a 00 } //00 00 
	condition:
		any of ($a_*)
 
}