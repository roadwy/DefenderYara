
rule TrojanDownloader_Win32_Tnega_BB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tnega.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0a 00 00 0a 00 "
		
	strings :
		$a_80_0 = {74 65 78 74 62 69 6e 2e 6e 65 74 2f 72 61 77 2f } //textbin.net/raw/  01 00 
		$a_81_1 = {61 70 69 5f 6c 6f 67 } //01 00  api_log
		$a_81_2 = {64 69 72 5f 77 61 74 63 68 } //01 00  dir_watch
		$a_81_3 = {76 6d 63 68 65 63 6b } //01 00  vmcheck
		$a_81_4 = {73 6e 78 68 6b } //01 00  snxhk
		$a_81_5 = {61 76 67 68 6f 6f 6b 78 } //01 00  avghookx
		$a_81_6 = {61 76 67 68 6f 6f 6b 61 } //01 00  avghooka
		$a_81_7 = {64 62 67 68 65 6c 70 } //01 00  dbghelp
		$a_81_8 = {70 73 74 6f 72 65 63 } //01 00  pstorec
		$a_81_9 = {63 6d 64 76 72 74 36 34 } //00 00  cmdvrt64
		$a_00_10 = {5d 04 00 00 a0 3a } //06 80 
	condition:
		any of ($a_*)
 
}