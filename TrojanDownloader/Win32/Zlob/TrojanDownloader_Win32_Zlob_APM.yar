
rule TrojanDownloader_Win32_Zlob_APM{
	meta:
		description = "TrojanDownloader:Win32/Zlob.APM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 1c 28 40 83 f8 90 01 01 7c f7 c6 04 28 00 90 00 } //01 00 
		$a_01_1 = {8b 52 38 8d 4c 24 0c 51 50 ff d2 8b 44 24 0c 83 f8 06 74 1f 83 f8 04 74 05 83 f8 05 75 d8 } //01 00 
		$a_01_2 = {62 69 74 73 2e 64 6c 6c 00 41 64 64 52 65 67 69 73 74 72 79 00 44 6f 77 6e 6c 6f 61 64 00 } //01 00  楢獴搮汬䄀摤敒楧瑳祲䐀睯汮慯d
		$a_03_3 = {7d 14 8b 55 08 03 55 fc 8a 02 2c 90 01 01 8b 4d 08 03 4d fc 88 01 eb db 90 00 } //01 00 
		$a_01_4 = {83 ea 05 89 55 f8 8b 45 08 89 45 fc 8b 4d fc c6 01 e9 6a 04 } //01 00 
		$a_01_5 = {69 70 64 6c 6c 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}