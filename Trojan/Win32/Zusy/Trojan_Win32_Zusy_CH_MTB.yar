
rule Trojan_Win32_Zusy_CH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {6b 71 78 63 73 74 66 6d 63 6e 64 77 7a 69 67 76 68 69 6f 74 63 6d 6f 68 73 2e 64 6c 6c } //1 kqxcstfmcndwzigvhiotcmohs.dll
		$a_01_1 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //1 Control_RunDLL
		$a_01_2 = {4c 6f 63 61 6c 5c 52 75 73 74 42 61 63 6b 74 72 61 63 65 4d 75 74 65 78 } //1 Local\RustBacktraceMutex
		$a_01_3 = {61 6b 79 6e 63 62 67 6f 6c 6c 6d 6a } //1 akyncbgollmj
		$a_01_4 = {62 6f 6a 6b 66 76 79 6e 68 68 75 70 6e 6f 6f 79 62 } //1 bojkfvynhhupnooyb
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_6 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
		$a_01_7 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } //1 GetTickCount64
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}