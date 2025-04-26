
rule TrojanDownloader_Win32_Banker_D{
	meta:
		description = "TrojanDownloader:Win32/Banker.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_02_1 = {68 74 74 70 3a 2f 2f 32 30 30 2e [0-0a] 2f 2e 6d 6d 73 2f 6c 73 64 ?? 2e 65 78 65 } //1
		$a_00_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 70 6f 6c 69 63 69 61 6a 75 64 69 63 69 61 72 69 61 2e 70 74 2f } //1 http://www.policiajudiciaria.pt/
		$a_00_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_00_4 = {55 52 4c 4d 4f 4e 2e 44 4c 4c } //1 URLMON.DLL
		$a_00_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}