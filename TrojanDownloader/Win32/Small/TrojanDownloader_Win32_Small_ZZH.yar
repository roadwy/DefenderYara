
rule TrojanDownloader_Win32_Small_ZZH{
	meta:
		description = "TrojanDownloader:Win32/Small.ZZH,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {b0 63 b1 0d 88 44 24 19 88 44 24 1a b0 2a 68 90 01 0c b0 0a c6 44 24 1c 41 c6 44 24 1f 65 c6 44 24 20 70 c6 44 24 21 74 c6 44 24 22 3a c6 44 24 23 20 c6 44 24 25 2f 88 4c 24 27 90 00 } //02 00 
		$a_01_1 = {46 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c } //01 00 
		$a_01_2 = {2f 69 6d 65 2e 73 6f 67 6f 75 2e 63 6f 6d 2f 64 6c 2f 73 6f 67 6f 75 5f 70 69 6e 79 69 6e 5f 6d 69 6e 69 5f 35 33 30 32 2e 65 78 65 } //01 00 
		$a_01_3 = {2f 64 6f 77 6e 6c 6f 61 64 2e 75 75 73 65 65 2e 63 6f 6d 2f 70 6f 70 32 2f 70 63 2f 55 55 53 65 65 5f 53 45 4f 31 5f 53 65 74 75 70 5f 31 30 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}