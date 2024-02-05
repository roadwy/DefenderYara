
rule TrojanDownloader_Win32_Banload_BEW{
	meta:
		description = "TrojanDownloader:Win32/Banload.BEW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 74 74 70 73 3a 2f 2f 73 74 6f 72 61 67 65 2e 67 6f 6f 67 6c 65 61 70 69 73 2e 63 6f 6d 2f 63 6f 6e 76 69 74 65 2d 32 30 31 35 2f } //01 00 
		$a_00_1 = {00 53 32 38 30 30 39 39 48 4a 36 36 36 33 00 } //01 00 
		$a_00_2 = {00 52 75 6e 6e 69 6e 67 61 6d 65 73 2e 65 78 65 00 } //01 00 
		$a_00_3 = {00 5c 74 6f 79 73 2e 64 61 74 00 } //01 00 
		$a_00_4 = {37 34 30 30 30 34 35 34 37 35 2e 6a 6b 39 00 } //01 00 
		$a_02_5 = {5c 61 4b 33 31 4d 41 53 54 45 52 30 90 02 02 2e 65 78 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}