
rule TrojanDownloader_Win32_Banload_AWQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 6f 61 6d 69 6e 67 90 02 10 2e 74 78 74 90 02 10 2e 65 78 65 90 02 10 2e 90 03 03 03 58 78 58 70 6e 67 90 00 } //01 00 
		$a_01_1 = {00 63 68 61 76 65 00 } //01 00 
		$a_01_2 = {00 32 41 46 31 30 45 45 33 32 32 33 39 } //01 00 
		$a_01_3 = {00 36 45 42 35 34 32 44 37 33 45 31 44 } //01 00 
		$a_03_4 = {33 db 8a 5c 38 ff 33 9d 90 01 02 ff ff 3b 9d f0 fe ff ff 7f 0e 81 c3 ff 00 00 00 2b 9d 90 01 02 ff ff eb 06 90 00 } //00 00 
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}