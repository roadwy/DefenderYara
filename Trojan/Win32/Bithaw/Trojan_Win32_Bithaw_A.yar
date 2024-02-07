
rule Trojan_Win32_Bithaw_A{
	meta:
		description = "Trojan:Win32/Bithaw.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 03 00 "
		
	strings :
		$a_01_0 = {6f 6e 20 73 76 63 68 6f 73 74 2e 65 78 65 20 69 6e 20 61 64 64 72 65 73 73 20 30 78 30 30 30 30 30 38 39 30 } //01 00  on svchost.exe in address 0x00000890
		$a_01_1 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  Toolhelp32ReadProcessMemory
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_3 = {42 6d 73 41 70 69 48 6f 6f 6b 5f 48 6f 6f 6b } //01 00  BmsApiHook_Hook
		$a_01_4 = {47 62 50 6c 75 67 69 6e 5c } //01 00  GbPlugin\
		$a_01_5 = {4c 64 72 55 6e 6c 6f 61 64 44 6c 6c } //01 00  LdrUnloadDll
		$a_01_6 = {50 72 69 6e 63 69 70 61 6c 5f 57 49 4e 44 4f 57 } //01 00  Principal_WINDOW
		$a_01_7 = {6c 45 2b 30 34 36 77 56 4a 2b 6b 71 6b 79 41 77 53 6a 5a 72 69 67 3d 3d } //00 00  lE+046wVJ+kqkyAwSjZrig==
	condition:
		any of ($a_*)
 
}