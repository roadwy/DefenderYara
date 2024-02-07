
rule TrojanDownloader_BAT_Agent_MA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Agent.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 72 01 00 00 70 72 90 01 01 00 00 70 6f 16 00 00 0a 00 02 7b 05 00 00 04 6f 17 00 00 0a 00 2a 90 00 } //01 00 
		$a_02_1 = {43 00 3a 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 90 02 03 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_02_2 = {43 3a 5c 52 6f 61 6d 69 6e 67 90 02 03 2e 65 78 65 90 00 } //01 00 
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_5 = {50 6c 65 61 73 65 57 61 69 74 2e 65 78 65 } //01 00  PleaseWait.exe
		$a_81_6 = {43 3a 5c 55 73 65 72 73 5c 50 43 5c 44 65 73 6b 74 6f 70 5c 50 6c 65 61 73 65 57 61 69 74 5c 50 6c 65 61 73 65 57 61 69 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 50 6c 65 61 73 65 57 61 69 74 2e 70 64 62 } //01 00  C:\Users\PC\Desktop\PleaseWait\PleaseWait\obj\Debug\PleaseWait.pdb
		$a_81_7 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //01 00  Form1_Load
		$a_81_8 = {64 6f 65 73 20 6e 6f 74 20 77 6f 72 6b 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //00 00  does not work on your computer
	condition:
		any of ($a_*)
 
}