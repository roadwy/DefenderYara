
rule VirTool_Win32_Injector_DZ{
	meta:
		description = "VirTool:Win32/Injector.DZ,SIGNATURE_TYPE_PEHSTR_EXT,16 00 15 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {75 04 33 c0 eb 29 83 7d 2c 00 74 11 8d 45 e8 6a 10 50 ff 75 2c e8 90 01 04 83 c4 0c f6 45 1c 04 75 09 ff 75 ec ff 15 90 01 04 6a 01 90 00 } //0a 00 
		$a_03_1 = {8d 7c 07 04 eb 03 8b 45 fc 8b 4d 0c 03 c3 ff 31 8b 4d ec 2b cb 51 50 e8 90 01 04 83 c4 0c 85 c0 0f 8c 39 02 00 00 90 00 } //01 00 
		$a_01_2 = {64 65 74 65 63 74 2e 64 6c 6c 00 } //01 00 
		$a_01_3 = {61 63 74 69 76 65 2e 64 6c 6c 00 } //01 00 
		$a_01_4 = {61 6c 67 2e 65 78 65 00 } //01 00 
		$a_01_5 = {75 73 65 72 69 6e 69 74 2e 65 78 65 00 } //00 00 
		$a_00_6 = {5d 04 00 00 51 fd 02 80 5c 21 00 00 52 fd 02 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}