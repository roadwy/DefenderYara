
rule Worm_Win32_Datheens_A{
	meta:
		description = "Worm:Win32/Datheens.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 13 00 0e 00 00 "
		
	strings :
		$a_00_0 = {3a 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //2 :\Autorun.inf
		$a_00_1 = {5b 41 75 74 6f 72 75 6e 5d } //2 [Autorun]
		$a_01_2 = {4f 50 45 4e 3d 44 65 61 74 68 2e 65 78 65 } //2 OPEN=Death.exe
		$a_01_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 44 65 61 74 68 2e 65 78 65 } //3 shellexecute=Death.exe
		$a_01_4 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 44 65 61 74 68 2e 65 78 65 } //3 shell\Auto\command=Death.exe
		$a_01_5 = {43 3a 5c 68 6f 73 74 73 } //2 C:\hosts
		$a_01_6 = {5c 53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 \SoftWare\Microsoft\Windows\CurrentVersion\Run
		$a_00_7 = {6e 65 74 20 73 74 6f 70 20 73 65 72 76 65 72 20 2f 79 } //2 net stop server /y
		$a_00_8 = {63 3a 5c 70 61 73 73 2e 64 69 63 } //2 c:\pass.dic
		$a_01_9 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_10 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_11 = {57 4e 65 74 41 64 64 43 6f 6e 6e 65 63 74 69 6f 6e 32 41 } //1 WNetAddConnection2A
		$a_01_12 = {4e 65 74 53 63 68 65 64 75 6c 65 4a 6f 62 41 64 64 } //1 NetScheduleJobAdd
		$a_01_13 = {4e 65 74 53 68 61 72 65 45 6e 75 6d } //1 NetShareEnum
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=19
 
}