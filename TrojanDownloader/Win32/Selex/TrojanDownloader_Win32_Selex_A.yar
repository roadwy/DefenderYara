
rule TrojanDownloader_Win32_Selex_A{
	meta:
		description = "TrojanDownloader:Win32/Selex.A,SIGNATURE_TYPE_PEHSTR,22 02 1f 02 0d 00 00 64 00 "
		
	strings :
		$a_01_0 = {6b 65 79 3d 6d 65 72 64 61 73 65 63 63 } //64 00  key=merdasecc
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //64 00  URLDownloadToFileA
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //64 00  Software\Microsoft\Internet Explorer\Main
		$a_01_3 = {2f 63 20 64 65 6c 20 } //64 00  /c del 
		$a_01_4 = {46 00 61 00 73 00 6c 00 61 00 6e 00 65 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 20 00 33 00 2e 00 33 00 34 00 62 00 } //01 00  Faslane Downloader 3.34b
		$a_01_5 = {43 72 65 61 74 65 53 74 72 65 61 6d 4f 6e 48 47 6c 6f 62 61 6c } //01 00  CreateStreamOnHGlobal
		$a_01_6 = {25 73 3f 70 61 72 61 6d 3d 25 64 } //01 00  %s?param=%d
		$a_01_7 = {48 6f 73 74 3a 20 25 73 } //01 00  Host: %s
		$a_01_8 = {50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e } //01 00  POST %s HTTP/1.
		$a_01_9 = {43 6f 6e 74 65 6e 74 2d 74 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //01 00  Content-type: application/x-www-form-urlencoded
		$a_01_10 = {43 6f 6e 74 65 6e 74 2d 6c 65 6e 67 74 68 3a 20 31 34 } //14 00  Content-length: 14
		$a_01_11 = {42 49 4e 41 52 59 } //14 00  BINARY
		$a_01_12 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 } //00 00  Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zone
	condition:
		any of ($a_*)
 
}