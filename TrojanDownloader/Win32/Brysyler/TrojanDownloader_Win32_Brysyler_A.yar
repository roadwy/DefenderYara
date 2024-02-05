
rule TrojanDownloader_Win32_Brysyler_A{
	meta:
		description = "TrojanDownloader:Win32/Brysyler.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {f3 ab 8a 06 2c 90 01 01 6a 01 88 44 24 90 01 01 8d 44 24 90 01 01 8d 4c 24 90 01 01 50 51 e8 90 01 04 8a 46 90 01 01 83 c4 0c 46 84 c0 75 de 90 00 } //01 00 
		$a_03_1 = {3c 42 52 3e 90 02 0a 3d 3d 63 68 90 02 0a 63 68 3d 3d 90 00 } //01 00 
		$a_03_2 = {75 70 67 72 90 02 05 2e 68 74 6d 90 02 15 77 77 77 2e 00 90 00 } //01 00 
		$a_01_3 = {5c 77 69 6e 73 79 73 33 32 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}