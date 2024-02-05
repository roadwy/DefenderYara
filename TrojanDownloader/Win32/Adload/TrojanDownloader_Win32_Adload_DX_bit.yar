
rule TrojanDownloader_Win32_Adload_DX_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d 77 65 73 74 2d 32 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 90 02 50 2f 4a 61 77 5a 69 67 61 2e 65 78 65 90 00 } //01 00 
		$a_01_1 = {7b 74 6d 70 7d 5c 4a 61 77 5a 69 67 61 2e 65 78 65 } //01 00 
		$a_01_2 = {00 2e 63 6f 6e 66 69 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Adload_DX_bit_2{
	meta:
		description = "TrojanDownloader:Win32/Adload.DX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6f 6c 64 2e 70 6f 77 65 72 73 74 72 69 6e 67 2e 62 69 64 2f 73 74 61 74 73 2e 70 68 70 3f 62 75 3d } //01 00 
		$a_03_1 = {62 75 6e 2e 77 61 72 73 70 61 64 65 2e 62 69 64 2f 6c 61 75 6e 63 68 5f 76 90 01 01 2e 70 68 70 3f 70 3d 26 70 69 64 3d 90 02 10 26 74 69 64 3d 90 00 } //01 00 
		$a_03_2 = {77 69 6e 2e 65 67 67 73 77 69 6c 64 65 72 6e 65 73 73 2e 62 69 64 2f 6c 61 75 6e 63 68 5f 76 90 01 01 2e 70 68 70 3f 70 3d 26 70 69 64 3d 90 02 10 26 74 69 64 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}