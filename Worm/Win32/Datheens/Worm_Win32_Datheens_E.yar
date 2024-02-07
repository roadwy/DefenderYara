
rule Worm_Win32_Datheens_E{
	meta:
		description = "Worm:Win32/Datheens.E,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 09 00 00 09 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //05 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {44 65 61 74 68 2e 65 78 65 } //05 00  Death.exe
		$a_00_2 = {44 65 61 74 68 2e 64 6c 6c } //05 00  Death.dll
		$a_00_3 = {44 65 64 6c 6c } //05 00  Dedll
		$a_00_4 = {64 6c 6c 66 69 6c 65 } //01 00  dllfile
		$a_00_5 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SoftWare\Microsoft\Windows\CurrentVersion\Run
		$a_00_6 = {5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00  \program files\internet explorer\iexplore.exe
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_8 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  Toolhelp32ReadProcessMemory
	condition:
		any of ($a_*)
 
}