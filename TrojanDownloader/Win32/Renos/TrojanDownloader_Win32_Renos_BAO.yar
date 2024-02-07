
rule TrojanDownloader_Win32_Renos_BAO{
	meta:
		description = "TrojanDownloader:Win32/Renos.BAO,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 02 00 "
		
	strings :
		$a_02_0 = {70 6c 75 73 2d 61 6e 74 69 76 69 72 75 73 2e 63 6f 6d 2f 90 17 08 0a 0f 0b 19 11 1c 19 14 74 65 72 6d 73 2e 68 74 6d 6c 63 62 2f 69 6e 73 74 61 6c 6c 73 2e 70 68 70 63 62 2f 72 65 61 6c 2e 70 68 70 69 6e 73 74 61 6c 6c 2f 41 6e 74 69 76 69 72 75 73 50 6c 75 73 2e 65 78 65 69 6e 73 74 61 6c 6c 2f 61 76 70 68 6c 2e 64 6c 6c 69 6e 73 74 61 6c 6c 2f 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 2e 64 6c 6c 69 6e 73 74 61 6c 6c 2f 41 6e 74 69 76 69 72 75 73 50 6c 75 73 2e 67 72 6e 69 6e 73 74 61 6c 6c 2f 61 64 64 2f 66 69 6c 65 2e 65 78 65 90 00 } //04 00 
		$a_00_1 = {5c 41 6e 74 69 76 69 72 75 73 20 50 6c 75 73 5c 41 6e 74 69 76 69 72 75 73 } //04 00  \Antivirus Plus\Antivirus
		$a_00_2 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 5c 41 6e 74 69 76 69 72 75 73 20 50 6c 75 73 } //01 00  Internet Explorer\Quick Launch\Antivirus Plus
		$a_02_3 = {5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 5c 90 01 0b 3a 2a 3a 45 6e 61 62 6c 65 64 3a 69 6e 73 74 61 6c 6c 65 72 90 00 } //01 00 
		$a_00_4 = {50 6c 65 61 73 65 2c 20 63 68 65 63 6b 20 79 6f 75 72 20 49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 21 } //01 00  Please, check your Internet connection!
		$a_00_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_00_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //00 00  InternetReadFile
	condition:
		any of ($a_*)
 
}