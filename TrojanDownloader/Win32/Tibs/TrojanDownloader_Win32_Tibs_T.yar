
rule TrojanDownloader_Win32_Tibs_T{
	meta:
		description = "TrojanDownloader:Win32/Tibs.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 c7 45 e0 14 00 66 c7 45 e2 14 00 c7 45 e4 90 01 04 66 c7 45 d8 1a 00 66 c7 45 da 1a 00 c7 45 dc 90 00 } //01 00 
		$a_02_1 = {8b 44 24 04 8b 40 04 05 b8 00 00 00 8b 08 80 39 cc 75 06 c7 00 90 01 04 83 c8 ff c2 04 00 90 00 } //01 00 
		$a_00_2 = {42 00 49 00 54 00 53 00 00 00 00 00 52 00 70 00 63 00 53 00 73 00 00 00 61 00 64 00 76 00 61 00 70 00 69 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 6f 00 6c 00 65 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}