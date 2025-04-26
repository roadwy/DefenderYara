
rule PWS_Win32_Wowsteal_XQ{
	meta:
		description = "PWS:Win32/Wowsteal.XQ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {4c 61 54 61 6c 65 43 6c 69 65 6e 74 2e 45 58 45 } //1 LaTaleClient.EXE
		$a_00_1 = {67 61 6d 65 63 6c 69 65 6e 74 2e 65 78 65 } //1 gameclient.exe
		$a_01_2 = {63 61 62 61 6c 6d 61 69 6e 2e 65 78 65 } //1 cabalmain.exe
		$a_00_3 = {57 4f 57 2e 45 58 45 } //1 WOW.EXE
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_01_6 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}