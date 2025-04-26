
rule TrojanDownloader_Win32_Agent_ZZB{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZZB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 7a 68 71 62 64 66 31 36 2e 69 6e 69 } //1 C:\Documents and Settings\All Users\zhqbdf16.ini
		$a_01_1 = {6d 79 64 6f 77 6e } //1 mydown
		$a_01_2 = {64 65 6c 61 79 } //1 delay
		$a_01_3 = {7a 68 71 62 5f 64 66 } //1 zhqb_df
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run
		$a_01_5 = {53 74 61 72 74 75 70 } //1 Startup
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_01_7 = {64 66 7a 68 71 62 2e 65 78 65 } //1 dfzhqb.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}