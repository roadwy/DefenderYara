
rule TrojanDownloader_Win32_Banload_XG{
	meta:
		description = "TrojanDownloader:Win32/Banload.XG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 6d 73 6e 5c 61 72 71 75 69 76 6f 73 2e 74 78 74 00 } //01 00 
		$a_00_1 = {41 33 35 45 43 44 37 42 41 34 32 41 41 42 34 33 45 38 36 39 45 39 31 42 43 32 30 30 35 46 38 35 46 41 35 41 39 37 33 44 00 } //01 00 
		$a_03_2 = {33 c0 55 68 90 01 04 64 ff 30 64 89 20 8b 15 90 01 04 a1 90 01 04 e8 90 01 04 84 c0 74 24 68 d0 07 00 00 e8 90 01 04 6a 01 6a 00 6a 00 a1 90 01 04 e8 90 01 04 50 6a 00 6a 00 e8 90 01 04 33 c0 5a 59 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}