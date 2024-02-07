
rule TrojanDownloader_Win32_Small_AHO{
	meta:
		description = "TrojanDownloader:Win32/Small.AHO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 61 00 64 00 65 00 72 00 5f 00 6a 00 69 00 65 00 6b 00 75 00 5f 00 39 00 37 00 37 00 2e 00 65 00 78 00 65 00 } //01 00  Loader_jieku_977.exe
		$a_01_1 = {68 00 61 00 6f 00 7a 00 69 00 70 00 5f 00 74 00 69 00 6e 00 79 00 2e 00 32 00 30 00 30 00 36 00 32 00 39 00 2e 00 65 00 78 00 65 00 } //01 00  haozip_tiny.200629.exe
		$a_03_2 = {64 00 6c 00 2e 00 6b 00 61 00 6e 00 6c 00 90 01 08 69 00 6e 00 6b 00 2e 00 63 00 6e 00 3a 00 31 00 32 00 90 01 06 38 00 37 00 2f 00 43 00 50 00 41 00 64 00 6f 00 77 00 6e 00 2f 00 90 00 } //01 00 
		$a_01_3 = {11 62 84 76 56 00 42 00 5c 00 a9 8b 7e 76 a6 5e 1c 64 22 7d d3 7e 9c 67 bb 53 07 63 9a 5b 30 57 40 57 5c 00 0b 4e 7d 8f 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 00 4e 74 65 57 59 d2 63 f6 4e 5c 00 0b 4e 7d 8f 89 5b c5 88 ba 4e b6 5b d2 63 f6 4e 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 } //00 00 
	condition:
		any of ($a_*)
 
}