
rule Worm_Win32_Usbalex_B{
	meta:
		description = "Worm:Win32/Usbalex.B,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //01 00  Microsoft Visual C++ Runtime Library
		$a_01_1 = {53 56 43 48 30 53 54 2e 45 58 45 } //01 00  SVCH0ST.EXE
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {72 65 63 79 63 6c 65 64 5c 64 65 73 6b 74 6f 70 2e 69 6e 69 } //01 00  recycled\desktop.ini
		$a_01_4 = {50 6f 6c 69 63 69 65 73 5c 43 6f 6d 64 6c 67 33 32 } //01 00  Policies\Comdlg32
		$a_01_5 = {50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b } //01 00  Policies\Network
		$a_01_6 = {50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //01 00  Policies\Explorer
		$a_01_7 = {75 00 73 00 62 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 31 00 2e 00 30 00 } //01 00  usb Version 1.0
		$a_01_8 = {75 00 73 00 62 00 2e 00 65 00 78 00 65 00 } //00 00  usb.exe
	condition:
		any of ($a_*)
 
}