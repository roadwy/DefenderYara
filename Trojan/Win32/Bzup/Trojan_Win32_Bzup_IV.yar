
rule Trojan_Win32_Bzup_IV{
	meta:
		description = "Trojan:Win32/Bzup.IV,SIGNATURE_TYPE_PEHSTR_EXT,18 00 17 00 0a 00 00 "
		
	strings :
		$a_00_0 = {61 67 65 6e 74 5f 64 71 2e 64 6c 6c } //10 agent_dq.dll
		$a_00_1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //2 Content-Type: application/x-www-form-urlencoded
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //2 CreateToolhelp32Snapshot
		$a_00_3 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //2 OpenProcess
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //2 InternetOpenUrlA
		$a_00_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //2 ShellExecuteA
		$a_00_6 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_00_7 = {46 74 70 43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //1 FtpCreateDirectoryA
		$a_00_8 = {46 74 70 46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //1 FtpFindFirstFileA
		$a_01_9 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //1 HttpSendRequestA
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*2+(#a_01_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1) >=23
 
}