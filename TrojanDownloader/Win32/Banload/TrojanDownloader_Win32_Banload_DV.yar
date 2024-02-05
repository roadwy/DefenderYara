
rule TrojanDownloader_Win32_Banload_DV{
	meta:
		description = "TrojanDownloader:Win32/Banload.DV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 90 02 40 2f 90 02 16 2e 90 03 03 03 65 78 65 6a 70 67 90 00 } //01 00 
		$a_00_1 = {49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } //01 00 
		$a_02_2 = {0f 00 00 00 63 3a 5c 90 01 08 2e 6a 70 67 90 00 } //01 00 
		$a_02_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6d 65 64 69 61 5c 90 02 08 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}