
rule Backdoor_Win32_Gulpix_MA_MTB{
	meta:
		description = "Backdoor:Win32/Gulpix.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 64 6e 2e 73 61 63 6b 6f 77 2e 63 6f 6d } //1 cdn.sackow.com
		$a_01_1 = {63 64 6e 2e 71 71 62 33 2e 63 6f 6d } //1 cdn.qqb3.com
		$a_01_2 = {6c 00 44 00 45 00 48 00 4a 00 4c 00 52 00 58 00 } //1 lDEHJLRX
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_4 = {53 6c 65 65 70 } //1 Sleep
		$a_01_5 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}