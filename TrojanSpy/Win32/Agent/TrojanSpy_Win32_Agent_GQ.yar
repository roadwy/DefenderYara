
rule TrojanSpy_Win32_Agent_GQ{
	meta:
		description = "TrojanSpy:Win32/Agent.GQ,SIGNATURE_TYPE_PEHSTR,ffffff99 00 ffffff99 00 09 00 00 "
		
	strings :
		$a_01_0 = {32 30 30 2e 32 30 36 2e 39 37 2e 34 32 } //10 200.206.97.42
		$a_01_1 = {41 43 54 49 56 58 2e 65 78 65 } //10 ACTIVX.exe
		$a_01_2 = {68 74 74 70 3a 2f 2f 75 70 6c 6f 61 64 2e 65 78 65 } //10 http://upload.exe
		$a_01_3 = {5c 6d 73 6a 61 76 61 33 32 5c 25 73 2e 6b 65 79 } //10 \msjava32\%s.key
		$a_01_4 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 78 78 78 7a 7a 7a 79 79 79 2e 65 78 65 } //10 C:\windows\xxxzzzyyy.exe
		$a_01_5 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_01_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_7 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_01_8 = {8b 4d 08 8b 55 0c 8a 01 32 02 8b 4d 08 88 01 8b 55 0c 83 c2 01 89 55 0c 8b 45 08 83 c0 01 89 45 08 } //100
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*100) >=153
 
}