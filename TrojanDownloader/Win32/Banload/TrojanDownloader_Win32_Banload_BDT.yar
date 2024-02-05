
rule TrojanDownloader_Win32_Banload_BDT{
	meta:
		description = "TrojanDownloader:Win32/Banload.BDT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 } //01 00 
		$a_01_1 = {45 72 72 6f 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f } //01 00 
		$a_03_2 = {45 6e 61 62 6c 65 4c 55 41 00 00 00 ff ff ff ff 23 00 00 00 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 90 08 f0 01 2e 72 61 72 90 00 } //00 00 
		$a_00_3 = {78 85 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_BDT_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.BDT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 5c 64 61 74 61 2e 7a 69 70 00 90 09 04 00 1c 00 00 00 90 00 } //01 00 
		$a_03_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 5c 6e 74 63 68 6b 33 32 2e 65 78 65 00 90 09 04 00 1f 00 00 00 90 00 } //01 00 
		$a_01_2 = {00 6f 70 65 6e 00 00 00 00 ff ff ff ff 0b 00 00 00 45 72 72 6f 72 20 39 30 30 34 35 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}