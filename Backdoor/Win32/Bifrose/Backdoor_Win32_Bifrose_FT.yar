
rule Backdoor_Win32_Bifrose_FT{
	meta:
		description = "Backdoor:Win32/Bifrose.FT,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8a 82 90 01 03 00 8a 54 1f ff 32 c2 5a 88 02 43 4e 75 90 00 } //0a 00 
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_2 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6e 6d 73 67 73 2e 65 78 65 } //01 00  \Program Files\Messenger\msnmsgs.exe
		$a_00_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_00_4 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  Toolhelp32ReadProcessMemory
		$a_00_5 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //00 00  SeDebugPrivilege
	condition:
		any of ($a_*)
 
}