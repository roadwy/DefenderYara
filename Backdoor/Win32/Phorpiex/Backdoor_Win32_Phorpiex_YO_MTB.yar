
rule Backdoor_Win32_Phorpiex_YO_MTB{
	meta:
		description = "Backdoor:Win32/Phorpiex.YO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6f 77 65 72 53 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 PowerShell -ExecutionPolicy Bypass (New-Object System.Net.WebClient).DownloadFile
		$a_01_1 = {62 69 74 73 61 64 6d 69 6e 20 2f 74 72 61 6e 73 66 65 72 } //1 bitsadmin /transfer
		$a_01_2 = {73 74 61 72 74 20 25 74 65 6d 70 25 5c } //1 start %temp%\
		$a_01_3 = {76 62 6f 78 74 72 61 79 2e 65 78 65 } //1 vboxtray.exe
		$a_01_4 = {50 61 73 73 77 6f 72 74 } //1 Passwort
		$a_01_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}