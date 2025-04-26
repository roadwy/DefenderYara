
rule Trojan_Win32_SystemHijack_B_dll{
	meta:
		description = "Trojan:Win32/SystemHijack.B!dll,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_00_0 = {41 66 78 3a 34 30 30 30 30 30 3a 30 3a 31 30 30 31 31 3a 30 3a 30 } //1 Afx:400000:0:10011:0:0
		$a_00_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 6f 6a 6c 31 31 31 2e 64 6c 6c } //10 C:\WINDOWS\ojl111.dll
		$a_00_2 = {53 6f 75 6c 64 6c 6c 2e 64 6c 6c } //10 Souldll.dll
		$a_00_3 = {64 61 71 75 3d 25 73 26 78 69 61 6f 71 75 3d 25 73 26 75 73 65 72 3d 25 73 26 70 61 73 73 3d 25 73 26 63 6b 70 61 73 73 3d 25 73 26 72 65 6e 77 75 3d 25 73 26 6c 65 76 65 6c 3d 25 64 26 67 6f 6c 64 3d 25 64 26 73 74 6f 6e 65 3d 25 64 26 63 70 6e 61 6d 65 3d 25 73 } //1 daqu=%s&xiaoqu=%s&user=%s&pass=%s&ckpass=%s&renwu=%s&level=%d&gold=%d&stone=%d&cpname=%s
		$a_00_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 38 38 76 63 64 2e 63 6f 6d 2f 68 74 6d 2f 63 68 69 6e 61 2f 6d 79 62 2f 73 65 6e 64 2e 61 73 70 3f 64 61 71 75 3d 25 73 26 78 69 61 6f 71 75 3d 25 73 26 75 73 65 72 3d 25 73 26 70 61 73 73 3d 25 73 26 63 6b 70 61 73 73 3d 25 73 26 72 65 6e 77 75 3d 25 73 26 6c 65 76 65 6c 3d 25 64 26 67 6f 6c 64 3d 25 64 26 73 74 6f 6e 65 3d 25 64 26 63 70 6e 61 6d 65 } //1 http://www.88vcd.com/htm/china/myb/send.asp?daqu=%s&xiaoqu=%s&user=%s&pass=%s&ckpass=%s&renwu=%s&level=%d&gold=%d&stone=%d&cpname
		$a_01_5 = {53 65 6e 64 5f 63 6b 31 } //1 Send_ck1
		$a_01_6 = {42 61 6e 6b 42 47 } //1 BankBG
		$a_00_7 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=26
 
}
rule Trojan_Win32_SystemHijack_B_dll_2{
	meta:
		description = "Trojan:Win32/SystemHijack.B!dll,SIGNATURE_TYPE_PEHSTR,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 66 78 3a 34 30 30 30 30 30 3a 30 3a 31 30 30 31 31 3a 30 3a 30 } //1 Afx:400000:0:10011:0:0
		$a_01_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 6f 6a 6c 31 31 31 2e 64 6c 6c } //10 C:\WINDOWS\ojl111.dll
		$a_01_2 = {6d 79 6e 65 77 2e 64 6c 6c } //10 mynew.dll
		$a_01_3 = {49 4d 45 49 4e 50 55 54 53 2e 45 58 45 } //1 IMEINPUTS.EXE
		$a_01_4 = {41 75 74 6f 50 61 74 63 68 2e 65 78 65 } //1 AutoPatch.exe
		$a_01_5 = {73 6f 75 6c 2e 65 78 65 } //1 soul.exe
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=26
 
}