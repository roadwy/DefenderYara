
rule Trojan_Win32_Keylogger_BD_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 55 73 65 72 4e 61 6d 65 3a 20 43 6f 75 6c 64 6e 27 74 20 67 65 74 20 74 68 65 20 75 73 65 72 20 6e 61 6d 65 20 21 21 } //1 sendUserName: Couldn't get the user name !!
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 25 73 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 57 69 6e 55 70 64 61 74 65 2e 65 78 65 } //1 C:\Users\%s\AppData\Local\WinUpdate.exe
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 25 73 5c 25 64 2d 25 64 2d 25 64 2e 62 6d 70 } //1 C:\Users\%s\%d-%d-%d.bmp
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 25 73 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 70 61 79 6c 6f 61 64 2e 70 73 31 } //1 C:\Users\%s\AppData\Local\payload.ps1
		$a_01_4 = {6b 65 79 4c 6f 67 67 65 72 4d 61 69 6e } //1 keyLoggerMain
		$a_01_5 = {5b 42 41 43 4b 53 50 41 43 45 5d } //1 [BACKSPACE]
		$a_01_6 = {5b 45 53 43 41 50 45 5d } //1 [ESCAPE]
		$a_01_7 = {44 61 74 61 20 77 72 69 74 74 65 6e 20 69 6e 20 74 68 65 20 66 69 6c 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Data written in the file successfully
		$a_01_8 = {77 72 69 74 65 4c 6f 67 73 3a 20 43 6f 75 6c 64 20 6e 6f 74 20 63 72 65 61 74 65 20 74 68 65 20 66 69 6c 65 20 66 6f 72 20 6b 65 79 6c 6f 67 20 6f 75 70 75 74 20 21 21 } //1 writeLogs: Could not create the file for keylog ouput !!
		$a_01_9 = {43 3a 5c 55 73 65 72 73 5c 25 73 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 2e 77 69 6e 64 6f 77 73 5f 64 65 66 65 6e 64 65 72 2e 63 6f 6e 66 } //1 C:\Users\%s\AppData\Local\.windows_defender.conf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}