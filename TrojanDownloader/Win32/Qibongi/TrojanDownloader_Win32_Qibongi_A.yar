
rule TrojanDownloader_Win32_Qibongi_A{
	meta:
		description = "TrojanDownloader:Win32/Qibongi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 00 78 6d 6c 77 69 6e 64 61 74 61 00 72 65 67 73 76 72 33 32 00 2f 73 20 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c [0-0a] 2e 64 6c 6c } //1
		$a_00_1 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\iexplore.exe
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}