
rule TrojanDownloader_Win32_Wowbar_F{
	meta:
		description = "TrojanDownloader:Win32/Wowbar.F,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {68 04 01 00 00 f3 ab 66 ab aa 8d 90 02 06 89 1d 90 01 04 50 ff 15 90 01 04 8d 90 02 06 89 1d 90 01 04 51 e8 90 01 04 53 e8 90 01 04 50 e8 90 01 04 e8 90 01 04 99 f7 3d 90 01 04 bf 90 01 04 83 c9 ff 68 04 01 00 00 8b c2 89 15 90 01 04 c1 e0 06 03 c2 8d 90 01 06 33 c0 f2 ae f7 d1 2b f9 8b f7 8b e9 8b fa 83 c9 ff f2 ae 8b cd 4f c1 e9 02 f3 a5 8b cd 8d 90 02 06 83 e1 03 50 f3 a4 e8 90 01 04 6a 01 e8 90 01 04 83 c4 18 85 c0 75 90 01 01 8d 90 02 06 51 e8 90 00 } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 63 6f 6d 6d 2e 77 6f 77 74 6f 6f 6c 62 61 72 2e 63 6f 2e 6b 72 } //01 00  http://comm.wowtoolbar.co.kr
		$a_00_2 = {42 41 43 4b 4d 41 4e } //01 00  BACKMAN
		$a_00_3 = {57 54 5f 47 45 54 5f 43 4f 4d 4d } //00 00  WT_GET_COMM
	condition:
		any of ($a_*)
 
}