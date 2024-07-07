
rule Trojan_Win32_CardSpy_DA_MTB{
	meta:
		description = "Trojan:Win32/CardSpy.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 67 65 6e 74 2e 70 64 62 } //1 Agent.pdb
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_2 = {5f 4d 59 44 45 42 55 47 3a } //1 _MYDEBUG:
		$a_01_3 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //1 SetEndOfFile
		$a_01_4 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
		$a_01_5 = {47 65 74 53 79 73 74 65 6d 54 69 6d 65 41 73 46 69 6c 65 54 69 6d 65 } //1 GetSystemTimeAsFileTime
		$a_01_6 = {42 6f 67 75 73 20 4a 50 45 47 20 63 6f 6c 6f 72 73 70 61 63 65 } //1 Bogus JPEG colorspace
		$a_01_7 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}