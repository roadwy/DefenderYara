
rule Backdoor_Win32_Wisdoor{
	meta:
		description = "Backdoor:Win32/Wisdoor,SIGNATURE_TYPE_PEHSTR,0a 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {77 69 73 64 6f 6d } //4 wisdom
		$a_01_1 = {38 38 46 69 6e 61 6c 53 6f 6c 75 74 69 6f 6e } //4 88FinalSolution
		$a_01_2 = {44 43 43 20 63 6f 6e 73 6f 6c 65 } //4 DCC console
		$a_01_3 = {73 63 72 69 70 74 73 2f 25 32 65 } //2 scripts/%2e
		$a_01_4 = {61 6d 61 74 65 75 72 20 76 69 64 65 6f } //1 amateur video
		$a_01_5 = {4b 65 79 53 70 79 } //1 KeySpy
		$a_01_6 = {63 61 70 74 75 72 69 6e 67 } //1 capturing
		$a_01_7 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b } //1 SetWindowsHook
		$a_01_8 = {55 53 45 52 20 25 73 } //1 USER %s
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}