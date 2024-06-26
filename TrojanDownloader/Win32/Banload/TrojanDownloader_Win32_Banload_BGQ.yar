
rule TrojanDownloader_Win32_Banload_BGQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 6d 00 75 00 73 00 74 00 2e 00 70 00 69 00 67 00 } //01 00  \must.pig
		$a_03_1 = {64 00 65 00 6e 00 74 00 6f 00 6f 00 6c 00 73 00 90 02 10 2e 00 37 00 7a 00 69 00 70 00 90 00 } //01 00 
		$a_01_2 = {59 00 44 00 44 00 40 00 0b 00 1f 00 1f } //00 00 
		$a_00_3 = {78 34 } //01 00  x4
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_BGQ_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 00 62 00 67 00 61 00 69 00 75 00 6c 00 2e 00 74 00 6d 00 70 00 } //01 00  abgaiul.tmp
		$a_01_1 = {70 00 6b 00 62 00 61 00 63 00 6b 00 23 00 } //01 00  pkback#
		$a_01_2 = {42 00 6c 00 6f 00 6b 00 75 00 2e 00 42 00 41 00 4b 00 } //01 00  Bloku.BAK
		$a_01_3 = {5c 00 2a 00 2e 00 65 00 78 00 65 00 } //01 00  \*.exe
		$a_01_4 = {2f 00 6e 00 6f 00 74 00 69 00 66 00 79 00 2e 00 70 00 68 00 70 00 } //01 00  /notify.php
		$a_01_5 = {2f 00 77 00 65 00 6c 00 67 00 6f 00 6d 00 65 00 2e 00 70 00 68 00 70 00 } //01 00  /welgome.php
		$a_01_6 = {5c 00 43 00 48 00 55 00 4d 00 47 00 2e 00 41 00 4c 00 45 00 52 00 54 00 } //01 00  \CHUMG.ALERT
		$a_01_7 = {5c 00 6d 00 73 00 74 00 38 00 2e 00 41 00 4c 00 45 00 52 00 54 00 } //01 00  \mst8.ALERT
		$a_01_8 = {5c 00 6d 00 73 00 74 00 31 00 31 00 2e 00 41 00 4c 00 45 00 52 00 54 00 } //02 00  \mst11.ALERT
		$a_03_9 = {64 89 20 33 c9 b2 01 a1 90 01 04 e8 90 01 04 89 45 f8 8b 45 f8 e8 90 01 04 ba 90 01 04 e8 90 01 04 8d 4d f4 ba 90 01 04 8b 45 f8 e8 90 01 04 33 c0 5a 59 59 64 89 10 68 90 01 04 8b 45 f8 e8 90 01 04 c3 e9 90 01 04 eb f0 90 00 } //00 00 
		$a_00_10 = {5d 04 00 } //00 41 
	condition:
		any of ($a_*)
 
}