
rule TrojanDownloader_Win32_Conhook_AE{
	meta:
		description = "TrojanDownloader:Win32/Conhook.AE,SIGNATURE_TYPE_PEHSTR_EXT,3b 00 3a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 78 00 73 00 65 00 61 00 72 00 63 00 68 00 7a 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 70 00 68 00 70 00 3f 00 71 00 3d 00 25 00 73 00 26 00 63 00 69 00 64 00 3d 00 25 00 53 00 26 00 61 00 69 00 64 00 3d 00 25 00 53 00 26 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 25 00 53 00 } //1 http://xsearchz.com/script.php?q=%s&cid=%S&aid=%S&version=%S
		$a_00_1 = {68 74 74 70 3a 2f 2f 78 73 65 61 72 63 68 7a 2e 63 6f 6d 2f 73 63 72 69 70 74 2e 70 68 70 } //1 http://xsearchz.com/script.php
		$a_00_2 = {68 74 74 70 3a 2f 2f 36 35 2e 32 34 33 2e 31 30 33 2e 36 32 2f 67 6f 2f 3f 63 6d 70 3d 76 6d 74 65 6b 5f 61 6c 65 78 76 73 26 6c 69 64 3d 25 73 26 75 69 64 3d 25 73 26 67 75 69 64 3d 25 73 } //1 http://65.243.103.62/go/?cmp=vmtek_alexvs&lid=%s&uid=%s&guid=%s
		$a_00_3 = {47 6c 6f 62 61 6c 5c 76 6d 63 5f 74 65 72 6d } //1 Global\vmc_term
		$a_00_4 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_00_5 = {73 65 72 76 69 63 65 73 2e 65 78 65 } //1 services.exe
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
		$a_01_8 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 42 } //1 rundll32.exe "%s",B
		$a_01_9 = {4c 6f 61 64 41 70 70 49 6e 69 74 5f 44 4c 4c 73 } //50 LoadAppInit_DLLs
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*50) >=58
 
}