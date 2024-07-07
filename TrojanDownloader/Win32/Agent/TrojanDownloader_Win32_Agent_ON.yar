
rule TrojanDownloader_Win32_Agent_ON{
	meta:
		description = "TrojanDownloader:Win32/Agent.ON,SIGNATURE_TYPE_PEHSTR,0f 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_01_1 = {63 3a 5c 73 73 73 2e 73 63 72 } //1 c:\sss.scr
		$a_01_2 = {63 3a 5c 73 73 73 31 2e 73 63 72 } //1 c:\sss1.scr
		$a_01_3 = {63 3a 5c 73 73 73 32 2e 73 63 72 } //1 c:\sss2.scr
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6c 75 62 6e 6f 65 67 61 2e 63 6f 6d 2f 5f 6e 6f 74 65 73 2f 61 72 71 75 69 76 6f 31 2e 65 78 65 } //1 http://www.clubnoega.com/_notes/arquivo1.exe
		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6c 75 62 6e 6f 65 67 61 2e 63 6f 6d 2f 5f 6e 6f 74 65 73 2f 61 72 71 75 69 76 6f 32 2e 65 78 65 } //1 http://www.clubnoega.com/_notes/arquivo2.exe
		$a_01_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6c 75 62 6e 6f 65 67 61 2e 63 6f 6d 2f 5f 6e 6f 74 65 73 2f 61 72 71 75 69 76 6f 33 2e 65 78 65 } //1 http://www.clubnoega.com/_notes/arquivo3.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=14
 
}