
rule TrojanSpy_Win32_Delf_AVG{
	meta:
		description = "TrojanSpy:Win32/Delf.AVG,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //05 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //05 00  CreateToolhelp32Snapshot
		$a_01_2 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //05 00  Process32Next
		$a_01_3 = {57 69 6e 45 78 65 63 } //05 00  WinExec
		$a_01_4 = {6d 69 78 65 72 4f 70 65 6e } //05 00  mixerOpen
		$a_01_5 = {4b 41 56 50 46 57 2e 45 58 45 } //05 00  KAVPFW.EXE
		$a_01_6 = {52 6f 67 75 65 43 6c 65 61 6e 65 72 2e 65 78 65 } //05 00  RogueCleaner.exe
		$a_01_7 = {5c 63 6f 6d 6d 6f 6e 64 73 2e 70 69 66 } //00 00  \commonds.pif
	condition:
		any of ($a_*)
 
}