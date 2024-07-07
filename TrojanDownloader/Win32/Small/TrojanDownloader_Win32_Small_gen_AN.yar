
rule TrojanDownloader_Win32_Small_gen_AN{
	meta:
		description = "TrojanDownloader:Win32/Small.gen!AN,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_1 = {54 65 72 6d 69 6e 61 74 65 54 68 72 65 61 64 } //1 TerminateThread
		$a_01_2 = {75 72 6c 6d 6f 6e 2e 64 6c 6c } //1 urlmon.dll
		$a_01_3 = {68 74 74 70 3a 2f 2f 62 65 73 74 62 73 64 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 69 67 31 } //1 http://bestbsd.info/cd/cd.php?id=%s&ver=ig1
		$a_01_4 = {68 74 74 70 3a 2f 2f 72 65 7a 75 6c 74 73 64 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 69 67 31 } //1 http://rezultsd.info/cd/cd.php?id=%s&ver=ig1
		$a_01_5 = {68 74 74 70 3a 2f 2f 63 61 72 72 65 6e 74 61 6c 68 65 6c 70 2e 6f 72 67 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 69 67 31 } //1 http://carrentalhelp.org/cd/cd.php?id=%s&ver=ig1
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44 5c 25 73 5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //1 SOFTWARE\Classes\CLSID\%s\InProcServer32
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 61 72 65 64 54 61 73 6b 53 63 68 65 64 75 6c 65 72 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}