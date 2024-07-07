
rule TrojanDownloader_Win32_Cashmin_A{
	meta:
		description = "TrojanDownloader:Win32/Cashmin.A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 61 20 45 78 70 6c 6f 72 61 } //1 Interneta Explora
		$a_01_1 = {68 74 74 70 3a 2f 2f 61 64 76 61 64 6d 69 6e 2e 62 69 7a 2f 74 61 73 6b 73 } //1 http://advadmin.biz/tasks
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 72 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\run
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 SOFTWARE\Microsoft\Internet Explorer\Main
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE
		$a_01_5 = {46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 FirewallDisableNotify
		$a_01_6 = {55 70 64 61 74 65 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 UpdatesDisableNotify
		$a_01_7 = {41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 AntiVirusDisableNotify
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}