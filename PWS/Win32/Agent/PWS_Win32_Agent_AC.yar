
rule PWS_Win32_Agent_AC{
	meta:
		description = "PWS:Win32/Agent.AC,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 57 69 6e 36 34 2e 4a 6d 70 } //1 SysWin64.Jmp
		$a_01_1 = {53 79 73 57 69 6e 36 34 2e 4c 73 74 } //1 SysWin64.Lst
		$a_01_2 = {43 4c 53 49 44 5c 7b 34 30 31 31 37 42 39 36 2d 39 39 38 44 2d 34 44 38 30 2d 38 46 38 39 2d 35 45 39 44 42 44 39 46 33 34 36 30 7d } //1 CLSID\{40117B96-998D-4D80-8F89-5E9DBD9F3460}
		$a_01_3 = {28 26 4f 29 5c 63 6f 6d 6d 61 6e 64 3d 41 75 74 6f 52 75 6e 2e 65 78 65 } //1 (&O)\command=AutoRun.exe
		$a_01_4 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 41 75 74 6f 52 75 6e 2e 65 78 65 } //1 shellexecute=AutoRun.exe
		$a_01_5 = {45 3a 5c 41 75 74 6f 52 75 6e 2e 65 78 65 } //1 E:\AutoRun.exe
		$a_01_6 = {45 3a 5c 41 75 74 6f 52 75 6e 2e 49 6e 66 } //1 E:\AutoRun.Inf
		$a_01_7 = {57 69 6e 53 79 73 36 34 2e 54 61 6f } //1 WinSys64.Tao
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}