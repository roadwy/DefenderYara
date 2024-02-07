
rule TrojanDownloader_BAT_Perseus_MA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Perseus.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 } //01 00  Create__Instance
		$a_01_1 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_2 = {44 74 5f 76 69 65 77 5f 4b 65 79 44 6f 77 6e } //01 00  Dt_view_KeyDown
		$a_01_3 = {69 00 72 00 65 00 6d 00 61 00 72 00 74 00 2e 00 65 00 73 00 2f 00 66 00 61 00 72 00 6d 00 61 00 75 00 74 00 69 00 6c 00 73 00 2f 00 61 00 63 00 31 00 } //01 00  iremart.es/farmautils/ac1
		$a_01_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_6 = {63 68 65 63 6b 5f 61 6e 74 69 76 69 72 75 73 5f 43 68 65 63 6b 65 64 43 68 61 6e 67 65 64 } //01 00  check_antivirus_CheckedChanged
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_8 = {2f 00 63 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 49 00 4d 00 20 00 47 00 77 00 78 00 2e 00 65 00 78 00 65 00 20 00 2f 00 46 00 } //01 00  /c taskkill /IM Gwx.exe /F
		$a_01_9 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}