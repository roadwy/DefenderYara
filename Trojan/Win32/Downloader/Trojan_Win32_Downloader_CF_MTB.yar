
rule Trojan_Win32_Downloader_CF_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {71 71 2e 65 78 65 } //1 qq.exe
		$a_01_1 = {74 69 6d 2e 65 78 65 } //1 tim.exe
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_3 = {30 2e 6c 6f 67 } //1 0.log
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 71 71 2e 63 6f 6d 2f 25 73 2f 61 64 64 69 6e 66 6f 2e 61 73 70 } //1 http://www.qq.com/%s/addinfo.asp
		$a_01_5 = {33 2e 64 6c 6c } //1 3.dll
		$a_01_6 = {48 6f 6f 6b 44 4c 4c } //1 HookDLL
		$a_01_7 = {76 63 6f 6e 2e 6b 65 79 } //1 vcon.key
		$a_01_8 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
		$a_01_9 = {31 2e 64 6c 6c } //1 1.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}