
rule TrojanDownloader_Win32_Banload_BAU{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 4b 49 54 52 39 4c 53 4a 44 4b 41 4c 33 4b 20 4c 4b 53 34 32 34 33 46 44 4b 4a 48 4a 45 37 34 33 32 49 55 4a 48 4b 39 57 59 5a 56 34 41 34 4d 4d 4f 41 30 4c 43 4d 57 57 55 41 4f 41 4a 36 4c 58 58 43 4d 4e 37 36 34 53 41 4a 31 45 35 49 57 30 39 46 44 33 32 4c 4b 33 32 4c 51 55 59 } //01 00  JKITR9LSJDKAL3K LKS4243FDKJHJE7432IUJHK9WYZV4A4MMOA0LCMWWUAOAJ6LXXCMN764SAJ1E5IW09FD32LK32LQUY
		$a_03_1 = {ff 75 1f e8 90 01 04 e8 90 01 04 83 3d 90 01 03 00 00 74 07 e8 90 01 04 eb 05 e8 90 01 04 33 c0 5a 59 59 64 89 10 68 90 01 04 8d 45 fc e8 90 01 04 c3 e9 90 01 04 eb f0 5b 59 5d c3 90 01 0a 42 52 90 00 } //01 00 
		$a_01_2 = {33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b 81 c3 ff 00 00 00 2b 5d ec eb 03 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}