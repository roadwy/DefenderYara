
rule TrojanDownloader_Win32_Renos_HC{
	meta:
		description = "TrojanDownloader:Win32/Renos.HC,SIGNATURE_TYPE_PEHSTR_EXT,22 00 21 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8d 51 10 33 c0 89 02 89 42 04 c7 01 01 23 45 67 c7 41 04 89 ab cd ef c7 41 08 fe dc ba 98 c7 41 0c 76 54 32 10 } //0a 00 
		$a_01_1 = {bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b } //0a 00 
		$a_03_2 = {68 00 14 2d 00 90 09 07 00 90 02 01 8d 90 03 01 02 45 44 24 90 01 01 6a 0c 90 00 } //01 00 
		$a_01_3 = {77 67 65 74 20 33 2e 30 00 } //01 00 
		$a_01_4 = {3e 20 6e 75 6c 00 } //01 00  ‾畮l
		$a_01_5 = {78 78 78 25 6c 75 2e 65 78 65 00 } //01 00 
		$a_00_6 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //00 00  \\.\PhysicalDrive0
	condition:
		any of ($a_*)
 
}