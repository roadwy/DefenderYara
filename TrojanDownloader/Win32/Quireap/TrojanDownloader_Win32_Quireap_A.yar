
rule TrojanDownloader_Win32_Quireap_A{
	meta:
		description = "TrojanDownloader:Win32/Quireap.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 04 00 "
		
	strings :
		$a_03_0 = {2f 6c 61 75 6e 63 68 5f 72 65 62 2e 70 68 70 3f 70 3d 73 65 76 65 6e 7a 69 70 90 02 10 26 74 69 64 3d 90 00 } //02 00 
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 } //02 00 
		$a_01_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4e 53 49 53 44 4c 2f 31 2e 32 20 28 4d 6f 7a 69 6c 6c 61 29 } //01 00 
		$a_01_3 = {4f 70 74 69 6d 69 7a 65 } //01 00 
		$a_01_4 = {5c 73 65 74 75 70 2e 65 78 65 } //00 00 
		$a_00_5 = {5d 04 00 00 98 62 03 } //80 5c 
	condition:
		any of ($a_*)
 
}