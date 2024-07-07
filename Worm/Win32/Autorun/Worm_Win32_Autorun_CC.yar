
rule Worm_Win32_Autorun_CC{
	meta:
		description = "Worm:Win32/Autorun.CC,SIGNATURE_TYPE_PEHSTR_EXT,24 00 23 00 0a 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 45 78 65 63 6c 2e 65 78 65 } //3 shell\Auto\command=Execl.exe
		$a_01_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 45 78 65 63 6c 2e 65 78 65 } //3 shellexecute=Execl.exe
		$a_01_2 = {6f 70 65 6e 3d 45 78 65 63 6c 2e 65 78 65 } //3 open=Execl.exe
		$a_01_3 = {5b 41 75 74 6f 52 75 6e 5d } //3 [AutoRun]
		$a_01_4 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //3 \autorun.inf
		$a_01_5 = {53 74 61 72 74 53 65 72 76 69 63 65 43 74 72 6c 44 69 73 70 61 74 63 68 65 72 41 } //5 StartServiceCtrlDispatcherA
		$a_01_6 = {43 72 65 61 74 65 54 68 72 65 61 64 } //5 CreateThread
		$a_01_7 = {57 69 6e 45 78 65 63 } //5 WinExec
		$a_01_8 = {47 65 74 44 72 69 76 65 54 79 70 65 41 } //5 GetDriveTypeA
		$a_01_9 = {54 58 4f 53 65 72 76 69 63 65 } //1 TXOService
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*1) >=35
 
}