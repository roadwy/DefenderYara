
rule TrojanDownloader_Win32_Small_AIJ{
	meta:
		description = "TrojanDownloader:Win32/Small.AIJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 e0 60 00 00 83 f9 04 72 1a 81 f9 82 01 00 00 73 08 81 f9 3c 01 00 00 77 02 31 03 83 c3 04 83 e9 04 eb e1 } //01 00 
		$a_01_1 = {68 65 69 79 69 6e 67 34 } //01 00 
		$a_01_2 = {2e 66 6e 73 6f 72 66 6e 66 67 73 61 6a 72 2e 63 6f 6d 2f 74 65 73 74 2e 68 74 6d } //01 00 
		$a_01_3 = {2f 2f 68 6f 6d 65 2e 35 31 2e 63 6f 6d 2f 3f 75 3d 6c 69 63 68 61 6f 33 35 39 36 26 63 3d 64 } //01 00 
		$a_01_4 = {3f 75 3d 74 65 73 74 64 6f 77 6e 26 63 3d 64 69 61 72 79 26 61 3d 67 65 74 64 61 74 61 76 69 65 77 26 69 64 3d } //00 00 
	condition:
		any of ($a_*)
 
}