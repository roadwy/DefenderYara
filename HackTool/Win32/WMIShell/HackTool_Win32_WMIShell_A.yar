
rule HackTool_Win32_WMIShell_A{
	meta:
		description = "HackTool:Win32/WMIShell.A,SIGNATURE_TYPE_PEHSTR,51 00 51 00 0a 00 00 "
		
	strings :
		$a_01_0 = {50 83 c7 0b 6a 40 6a 03 57 56 ff d3 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //10 VirtualProtectEx
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_01_3 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 53 69 64 41 } //10 LookupAccountSidA
		$a_01_4 = {44 75 70 6c 69 63 61 74 65 54 6f 6b 65 6e 45 78 } //10 DuplicateTokenEx
		$a_01_5 = {77 6d 69 70 72 76 73 65 2e 65 78 65 } //10 wmiprvse.exe
		$a_01_6 = {7b 31 46 38 37 31 33 37 44 2d 30 45 37 43 2d 34 34 64 35 2d 38 43 37 33 2d 34 45 46 46 42 36 38 39 36 32 46 32 7d } //10 {1F87137D-0E7C-44d5-8C73-4EFFB68962F2}
		$a_01_7 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 } //10 WinSta0\Default
		$a_01_8 = {2f 78 78 6f 6f 2f 2d 2d 3e 47 6f 74 20 57 4d 49 20 70 72 6f 63 65 73 73 20 50 69 64 3a 20 25 64 } //1 /xxoo/-->Got WMI process Pid: %d
		$a_01_9 = {2f 78 78 6f 6f 2f 2d 2d 3e 54 68 69 73 20 65 78 70 6c 6f 69 74 20 67 69 76 65 73 20 79 6f 75 20 61 20 4c 6f 63 61 6c 20 53 79 73 74 65 6d 20 73 68 65 6c 6c } //1 /xxoo/-->This exploit gives you a Local System shell
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=81
 
}