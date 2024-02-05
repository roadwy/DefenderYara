
rule TrojanDownloader_Win32_Banload_AWN{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6c 69 62 6d 79 73 71 6c 2e 64 6c 6c 00 90 02 10 68 74 74 70 3a 2f 2f 90 02 30 2e 90 17 03 03 03 03 67 69 66 6a 70 67 6c 6f 67 00 90 02 06 ff ff 90 01 01 00 00 00 90 04 10 10 41 42 43 44 45 46 31 32 33 34 35 36 37 38 39 30 90 00 } //01 00 
		$a_01_1 = {00 63 68 61 76 65 00 } //01 00 
		$a_03_2 = {6a 01 8d 45 ec b9 90 01 04 8b 15 90 01 04 e8 90 01 04 8b 45 ec e8 90 01 04 50 e8 90 01 04 e8 90 01 01 fe ff ff 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}