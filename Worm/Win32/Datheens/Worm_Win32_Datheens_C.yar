
rule Worm_Win32_Datheens_C{
	meta:
		description = "Worm:Win32/Datheens.C,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 0b 00 00 03 00 "
		
	strings :
		$a_01_0 = {6e 65 74 20 73 74 6f 70 20 53 79 6d 61 6e 74 65 63 } //02 00  net stop Symantec
		$a_01_1 = {2e 48 54 4d 4c 00 00 00 ff ff ff ff 04 00 } //02 00 
		$a_01_2 = {2e 41 53 50 58 00 00 00 ff ff ff ff 1b 00 } //02 00 
		$a_00_3 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //02 00  :\autorun.inf
		$a_01_4 = {3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 6a 61 76 61 73 63 72 69 70 74 22 20 73 72 63 3d } //02 00  <script language="javascript" src=
		$a_00_5 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_6 = {6f 70 65 6e 3d } //01 00  open=
		$a_00_7 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d } //01 00  shellexecute=
		$a_01_8 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d } //01 00  shell\Auto\command=
		$a_01_9 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //01 00  GetSystemDirectoryA
		$a_01_10 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  Toolhelp32ReadProcessMemory
	condition:
		any of ($a_*)
 
}