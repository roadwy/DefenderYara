
rule TrojanDownloader_Win32_Stalni{
	meta:
		description = "TrojanDownloader:Win32/Stalni,SIGNATURE_TYPE_PEHSTR,09 00 07 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {3e c7 02 63 6d 64 20 3e c7 42 04 2f 63 20 22 } //02 00 
		$a_01_1 = {3e c7 00 22 20 49 4e 3e c7 40 04 53 54 41 4c } //01 00 
		$a_01_2 = {81 78 05 90 90 90 90 74 } //01 00 
		$a_01_3 = {81 38 83 7c 24 04 74 } //01 00 
		$a_01_4 = {68 6f 6e 00 00 68 75 72 6c 6d } //01 00 
		$a_01_5 = {6a 6c 68 6e 74 64 6c } //01 00 
		$a_01_6 = {36 8b 6c 24 24 36 8b 45 3c 36 8b 54 05 78 } //01 00 
		$a_01_7 = {3e 8b 4a 18 3e 8b 5a 20 } //01 00 
		$a_01_8 = {64 8b 15 30 00 00 00 8d 52 03 80 3a 01 0f } //00 00 
	condition:
		any of ($a_*)
 
}