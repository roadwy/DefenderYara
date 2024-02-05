
rule TrojanDownloader_Win32_Banload_BGL{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 41 00 4b 00 41 00 2e 00 42 00 41 00 4b 00 } //01 00 
		$a_01_1 = {42 00 55 00 4a 00 55 00 2e 00 42 00 41 00 4b 00 } //01 00 
		$a_01_2 = {70 00 6b 00 62 00 61 00 63 00 6b 00 23 00 } //01 00 
		$a_01_3 = {2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 61 00 70 00 69 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 } //01 00 
		$a_01_4 = {28 00 42 00 72 00 61 00 73 00 69 00 6c 00 29 00 } //01 00 
		$a_03_5 = {8b 45 94 50 8d 45 8c ba 90 01 04 e8 90 01 04 8b 45 8c 5a e8 90 01 04 85 c0 7e 05 83 cb ff eb 02 90 00 } //00 00 
		$a_00_6 = {5d 04 00 } //00 c7 
	condition:
		any of ($a_*)
 
}