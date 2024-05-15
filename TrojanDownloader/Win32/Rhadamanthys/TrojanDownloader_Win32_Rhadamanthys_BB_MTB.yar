
rule TrojanDownloader_Win32_Rhadamanthys_BB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rhadamanthys.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0b 00 00 0a 00 "
		
	strings :
		$a_80_0 = {74 65 78 74 62 69 6e 2e 6e 65 74 2f 72 61 77 2f } //textbin.net/raw/  0a 00 
		$a_01_1 = {69 00 70 00 2d 00 61 00 70 00 69 00 2e 00 63 00 6f 00 6d 00 2f 00 6c 00 69 00 6e 00 65 00 2f 00 3f 00 66 00 69 00 65 00 6c 00 64 00 73 00 3d 00 68 00 6f 00 73 00 74 00 69 00 6e 00 67 00 } //01 00  ip-api.com/line/?fields=hosting
		$a_81_2 = {61 70 69 5f 6c 6f 67 } //01 00  api_log
		$a_81_3 = {64 69 72 5f 77 61 74 63 68 } //01 00  dir_watch
		$a_81_4 = {76 6d 63 68 65 63 6b } //01 00  vmcheck
		$a_81_5 = {73 6e 78 68 6b } //01 00  snxhk
		$a_81_6 = {61 76 67 68 6f 6f 6b 78 } //01 00  avghookx
		$a_81_7 = {61 76 67 68 6f 6f 6b 61 } //01 00  avghooka
		$a_81_8 = {64 62 67 68 65 6c 70 } //01 00  dbghelp
		$a_81_9 = {70 73 74 6f 72 65 63 } //01 00  pstorec
		$a_81_10 = {63 6d 64 76 72 74 36 34 } //00 00  cmdvrt64
		$a_00_11 = {5d 04 00 00 a6 6e } //06 80 
	condition:
		any of ($a_*)
 
}