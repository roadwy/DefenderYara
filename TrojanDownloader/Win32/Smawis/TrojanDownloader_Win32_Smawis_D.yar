
rule TrojanDownloader_Win32_Smawis_D{
	meta:
		description = "TrojanDownloader:Win32/Smawis.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {b9 05 00 00 00 be 90 01 04 8d bc 24 90 01 04 8b e8 f3 a5 b9 7d 00 00 00 33 c0 8d bc 24 90 01 04 33 d2 f3 ab 90 00 } //02 00 
		$a_03_1 = {81 fe 09 0c 00 00 74 0c 81 fe 09 08 00 00 0f 85 90 01 04 68 90 01 04 8d 90 01 01 24 90 01 04 68 90 01 05 8d 90 01 01 24 90 01 04 68 90 01 05 ff d3 90 00 } //02 00 
		$a_01_2 = {77 00 73 00 2e 00 70 00 68 00 70 00 3f 00 78 00 3d 00 00 00 } //01 00 
		$a_01_3 = {20 3e 3e 20 4e 55 4c 00 2f 63 20 64 65 6c 20 00 } //01 00 
		$a_01_4 = {2f 00 73 00 6d 00 6f 00 63 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}