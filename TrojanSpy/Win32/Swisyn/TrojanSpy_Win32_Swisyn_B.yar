
rule TrojanSpy_Win32_Swisyn_B{
	meta:
		description = "TrojanSpy:Win32/Swisyn.B,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 50 50 4c 49 43 41 54 49 4f 4e 20 3a 20 4b 45 59 4c 4f 47 47 45 52 } //1 APPLICATION : KEYLOGGER
		$a_01_1 = {5b 42 61 63 6b 73 70 61 63 65 5d } //1 [Backspace]
		$a_01_2 = {3f 61 63 74 69 6f 6e 3d 61 64 64 26 75 73 65 72 6e 61 6d 65 3d } //1 ?action=add&username=
		$a_01_3 = {5c 50 43 54 6f 74 61 6c 44 65 66 65 6e 64 65 72 5c 73 71 6c 69 74 65 33 2e 64 6c 6c } //1 \PCTotalDefender\sqlite3.dll
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {50 72 6f 63 65 73 73 20 4d 6f 6e 69 74 6f 72 20 2d 20 53 79 73 69 6e 74 65 72 6e 61 6c 73 3a 20 77 77 77 2e 73 79 73 69 6e 74 65 72 6e 61 6c 73 2e 63 6f 6d } //1 Process Monitor - Sysinternals: www.sysinternals.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}