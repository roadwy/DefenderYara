
rule TrojanDownloader_WinNT_Jban_A{
	meta:
		description = "TrojanDownloader:WinNT/Jban.A,SIGNATURE_TYPE_JAVAHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f } //01 00 
		$a_03_1 = {57 10 08 b8 00 90 01 01 b6 00 90 01 01 12 90 01 01 b6 00 90 1b 01 12 90 01 01 b6 00 90 1b 01 12 90 01 01 b6 00 90 1b 01 b6 00 90 01 01 3a 90 00 } //01 00 
		$a_00_2 = {41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 } //00 00 
		$a_00_3 = {5d 04 00 00 f5 a9 02 80 5c 23 00 } //00 f6 
	condition:
		any of ($a_*)
 
}