
rule Worm_Win32_SillyShareCopy_P{
	meta:
		description = "Worm:Win32/SillyShareCopy.P,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 } //01 00  Wscript.Shell
		$a_00_1 = {48 00 4b 00 4c 00 4d 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 52 00 75 00 6e 00 64 00 6c 00 6c 00 } //01 00  HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Rundll
		$a_00_2 = {72 00 65 00 67 00 77 00 72 00 69 00 74 00 65 00 } //01 00  regwrite
		$a_00_3 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //01 00  [autorun]
		$a_00_4 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  shell\open\Command=rundll.exe
		$a_00_5 = {5c 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //01 00  \Autorun.inf
		$a_00_6 = {44 00 72 00 69 00 76 00 65 00 4c 00 65 00 74 00 74 00 65 00 72 00 } //01 00  DriveLetter
		$a_01_7 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_8 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //00 00  GetSystemDirectoryA
	condition:
		any of ($a_*)
 
}