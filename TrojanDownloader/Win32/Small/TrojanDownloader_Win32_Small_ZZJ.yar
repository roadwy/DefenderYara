
rule TrojanDownloader_Win32_Small_ZZJ{
	meta:
		description = "TrojanDownloader:Win32/Small.ZZJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 50 47 6f 6f 64 53 74 61 74 75 73 } //01 00 
		$a_01_1 = {25 41 50 50 44 41 54 41 25 5c 63 77 69 6e 74 6f 6f 6c 2e 65 78 65 } //01 00 
		$a_01_2 = {7b 00 36 00 34 00 45 00 45 00 30 00 44 00 34 00 35 00 2d 00 45 00 43 00 39 00 42 00 2d 00 34 00 44 00 38 00 43 00 2d 00 39 00 39 00 44 00 35 00 2d 00 36 00 35 00 32 00 42 00 38 00 37 00 36 00 35 00 37 00 46 00 35 00 34 00 7d 00 } //01 00 
		$a_01_3 = {2f 73 65 61 72 63 68 2e 63 77 69 6e 74 6f 6f 6c 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 61 73 70 3f 70 69 64 3d 25 73 26 6d 61 63 3d 25 73 26 71 79 3d } //01 00 
		$a_01_4 = {c1 a4 bb f3 c0 fb c0 b8 b7 ce 20 bb e8 c1 a6 b5 c7 be fa bd c0 b4 cf b4 d9 00 00 00 c8 ae c0 ce } //00 00 
	condition:
		any of ($a_*)
 
}