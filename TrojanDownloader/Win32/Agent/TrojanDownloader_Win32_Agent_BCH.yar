
rule TrojanDownloader_Win32_Agent_BCH{
	meta:
		description = "TrojanDownloader:Win32/Agent.BCH,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6d 65 67 6f 74 6f 2e 63 6f 6d 2f 68 6f 73 74 2e 6a 70 67 } //10 http://www.comegoto.com/host.jpg
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //5 URLDownloadToFileA
		$a_01_2 = {4d 41 49 4e 5f 53 54 41 52 54 00 } //1
		$a_00_3 = {64 65 6c 6d 65 2e 62 61 74 } //1 delme.bat
		$a_01_4 = {53 00 45 00 54 00 54 00 49 00 4e 00 47 00 53 00 } //1 SETTINGS
		$a_01_5 = {64 65 6c 20 25 73 } //1 del %s
		$a_01_6 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 74 72 79 } //1 if exist "%s" goto try
		$a_01_7 = {64 65 6c 20 22 25 73 22 } //1 del "%s"
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=20
 
}
rule TrojanDownloader_Win32_Agent_BCH_2{
	meta:
		description = "TrojanDownloader:Win32/Agent.BCH,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6d 65 67 6f 74 6f 2e 63 6f 6d 2f 68 6f 73 74 2e 6a 70 67 } //10 http://www.comegoto.com/host.jpg
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //5 URLDownloadToFileA
		$a_01_2 = {4d 61 69 6e 5f 53 74 61 72 74 5f 51 00 } //1
		$a_01_3 = {6e 6f 6e 6f 6d 65 2e 62 61 74 } //1 nonome.bat
		$a_01_4 = {4d 00 41 00 4b 00 45 00 52 00 45 00 53 00 00 00 } //1
		$a_01_5 = {64 65 6c 20 25 73 } //1 del %s
		$a_01_6 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 74 72 79 } //1 if exist "%s" goto try
		$a_01_7 = {64 65 6c 20 22 25 73 22 } //1 del "%s"
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=20
 
}