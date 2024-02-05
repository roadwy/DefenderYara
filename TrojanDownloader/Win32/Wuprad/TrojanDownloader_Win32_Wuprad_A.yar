
rule TrojanDownloader_Win32_Wuprad_A{
	meta:
		description = "TrojanDownloader:Win32/Wuprad.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 66 66 69 64 3d 25 73 26 61 63 74 69 6f 6e 3d 64 6f 77 6e 5f 6c 6f 61 64 } //01 00 
		$a_03_1 = {10 27 00 00 7d 0a 6a 05 e8 90 01 04 83 c4 04 6a 01 90 00 } //01 00 
		$a_03_2 = {8b 44 24 04 ff 24 95 90 01 04 68 90 01 04 51 68 90 01 04 50 ff 15 90 01 04 83 c4 10 b8 01 00 00 00 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}