
rule TrojanDownloader_Win32_Mimikatz_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Mimikatz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_1 = {63 6d 64 20 2f 63 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c } //1 cmd /c C:\Users\Public\Documents\
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d } //1 cmd.exe /c taskkill /f /t /im
		$a_01_3 = {50 72 6f 6d 70 74 4f 6e 53 65 63 75 72 65 44 65 73 6b 74 6f 70 } //1 PromptOnSecureDesktop
		$a_01_4 = {45 6e 61 62 6c 65 4c 55 41 } //1 EnableLUA
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
		$a_01_6 = {3a 2f 2f 64 65 70 61 72 74 6d 65 6e 74 2e 6d 69 63 72 6f 73 6f 66 74 6d 69 64 64 6c 65 6e 61 6d 65 2e 74 6b 2f } //1 ://department.microsoftmiddlename.tk/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}