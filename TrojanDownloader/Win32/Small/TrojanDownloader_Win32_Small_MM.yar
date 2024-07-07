
rule TrojanDownloader_Win32_Small_MM{
	meta:
		description = "TrojanDownloader:Win32/Small.MM,SIGNATURE_TYPE_PEHSTR,20 00 20 00 08 00 00 "
		
	strings :
		$a_01_0 = {69 6e 66 6f 3d 25 73 } //1 info=%s
		$a_01_1 = {50 4f 53 54 20 2f 69 6e 74 65 72 66 61 63 65 2e 61 73 70 20 48 54 54 50 2f 31 2e 31 } //10 POST /interface.asp HTTP/1.1
		$a_01_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 28 43 75 73 74 6f 6d 53 70 79 29 } //10 User-Agent: (CustomSpy)
		$a_01_3 = {47 45 54 20 2f 71 76 6f 64 2e 74 78 74 20 48 54 54 50 2f 31 2e 31 } //10 GET /qvod.txt HTTP/1.1
		$a_01_4 = {25 73 5c 62 61 69 64 75 } //1 %s\baidu
		$a_01_5 = {25 73 5c 62 61 69 64 75 5c 25 73 } //10 %s\baidu\%s
		$a_01_6 = {50 72 6f 6a 65 63 74 73 5c 78 4e 65 74 49 6e 73 74 61 6c 6c 65 72 5c 52 65 6c 65 61 73 65 5c 78 4e 65 74 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //10 Projects\xNetInstaller\Release\xNetInstaller.pdb
		$a_01_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1) >=32
 
}