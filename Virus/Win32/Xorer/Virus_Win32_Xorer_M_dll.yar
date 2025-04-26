
rule Virus_Win32_Xorer_M_dll{
	meta:
		description = "Virus:Win32/Xorer.M!dll,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {68 6f 6f 6b 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 48 4f 4f 4b 00 55 6e 69 6e 73 74 61 6c 6c 48 4f 4f 4b 00 } //1
		$a_01_1 = {4d 43 49 20 50 72 6f 67 72 } //1 MCI Progr
		$a_01_2 = {73 68 75 74 64 6f 77 6e 2e 65 78 65 20 2d 72 20 2d 66 20 2d 74 20 30 } //1 shutdown.exe -r -f -t 0
		$a_01_3 = {5c 7e 2e 65 78 65 } //1 \~.exe
		$a_01_4 = {5c 63 6f 6d 5c 6c 73 61 73 73 2e 65 78 65 } //1 \com\lsass.exe
		$a_01_5 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_01_6 = {46 69 6e 64 57 69 6e 64 6f 77 41 } //1 FindWindowA
		$a_01_7 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_01_9 = {53 74 61 72 74 75 70 } //1 Startup
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}