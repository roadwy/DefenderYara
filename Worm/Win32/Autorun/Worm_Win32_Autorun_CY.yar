
rule Worm_Win32_Autorun_CY{
	meta:
		description = "Worm:Win32/Autorun.CY,SIGNATURE_TYPE_PEHSTR,49 00 49 00 0d 00 00 "
		
	strings :
		$a_01_0 = {64 45 4c 20 25 30 20 2f 61 } //10 dEL %0 /a
		$a_01_1 = {5b 41 75 74 6f 52 75 6e 5d } //10 [AutoRun]
		$a_01_2 = {53 68 65 6c 6c 5c 4f 70 65 6e 3d } //10 Shell\Open=
		$a_01_3 = {41 75 74 6f 52 75 6e 2e 69 6e 66 } //10 AutoRun.inf
		$a_01_4 = {5c 53 59 53 54 45 4d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //10 \SYSTEM32\svchost.exe
		$a_01_5 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //10 \Device\PhysicalMemory
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_7 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_8 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_9 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
		$a_01_10 = {6d 79 6c 6f 76 65 } //1 mylove
		$a_01_11 = {6c 6f 76 65 79 6f 75 } //1 loveyou
		$a_01_12 = {62 61 62 79 31 32 33 } //1 baby123
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=73
 
}