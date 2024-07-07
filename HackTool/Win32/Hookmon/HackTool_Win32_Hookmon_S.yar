
rule HackTool_Win32_Hookmon_S{
	meta:
		description = "HackTool:Win32/Hookmon.S,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 6f 6f 6b 20 63 61 6e 20 4e 4f 54 20 62 65 20 53 74 6f 70 65 64 } //1 Hook can NOT be Stoped
		$a_01_1 = {44 4c 4c 20 69 73 20 6c 6f 61 64 65 64 } //1 DLL is loaded
		$a_01_2 = {7b 36 32 43 34 43 43 45 42 2d 34 44 32 46 2d 34 44 45 38 2d 38 36 44 35 2d 33 42 35 46 35 31 34 39 45 33 43 33 7d } //1 {62C4CCEB-4D2F-4DE8-86D5-3B5F5149E3C3}
		$a_01_3 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 \Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}