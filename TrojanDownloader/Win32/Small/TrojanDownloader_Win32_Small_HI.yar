
rule TrojanDownloader_Win32_Small_HI{
	meta:
		description = "TrojanDownloader:Win32/Small.HI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 43 6f 6d 53 70 65 63 25 20 2f 63 20 45 52 41 53 45 20 2f 46 20 } //01 00 
		$a_01_1 = {73 65 63 00 25 74 65 6d 70 25 00 53 74 75 62 50 61 74 68 00 25 77 69 6e 64 69 72 25 00 73 76 63 68 6f 73 74 2e 65 78 65 00 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 } //01 00 
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c } //01 00 
		$a_00_3 = {6a 00 ff 55 0c 8d 3d ad 18 14 13 68 04 01 00 00 57 68 c9 1a 14 13 ff 55 5c 48 03 f8 8d 35 3a 1b 14 13 ac 0a c0 aa 75 fa 68 ad 18 14 13 68 b1 19 14 13 ff 55 50 0b c0 74 76 6a 00 68 ad 18 14 13 68 } //00 00 
	condition:
		any of ($a_*)
 
}