
rule VirTool_Win32_DelfInject_AP{
	meta:
		description = "VirTool:Win32/DelfInject.AP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {7c 20 40 c7 03 00 00 00 00 8b 15 28 e4 4b 00 03 13 8a 12 8b 0d 24 e4 4b 00 03 0b 88 11 ff 03 48 75 e7 } //02 00 
		$a_01_1 = {c6 06 ff eb 17 84 d2 75 05 c6 06 00 eb 0e 8b 15 28 e4 4b 00 03 13 0f b6 12 4a 88 16 ff 03 48 75 d0 } //01 00 
		$a_01_2 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 21 e8 } //02 00 
		$a_01_3 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 55 00 70 00 64 00 61 00 74 00 5f 00 39 00 36 00 37 00 39 00 33 00 2e 00 65 00 78 00 65 00 } //01 00  \WindowsUpdat_96793.exe
		$a_03_4 = {7e 7a 57 7c 00 00 00 00 90 01 01 7a 48 00 0a 09 90 00 } //01 00 
		$a_03_5 = {51 4c 04 05 15 00 00 00 09 00 90 02 30 2f 66 79 66 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}