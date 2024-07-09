
rule Worm_Win32_Autorun_EI{
	meta:
		description = "Worm:Win32/Autorun.EI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d [0-20] 2e 73 63 72 } //1
		$a_00_1 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_00_2 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_00_3 = {54 61 73 6b 4d 6f 6e 69 74 6f 72 } //1 TaskMonitor
		$a_00_4 = {52 65 61 6c 73 68 61 64 65 } //1 Realshade
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_6 = {77 6d 6e 7a 65 6c 66 2e 62 61 74 } //1 wmnzelf.bat
		$a_00_7 = {6b 62 64 6f 78 68 65 6c 70 2e 64 6c 6c } //1 kbdoxhelp.dll
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}