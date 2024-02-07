
rule TrojanDropper_O97M_Donoff_AA{
	meta:
		description = "TrojanDropper:O97M/Donoff.AA,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 69 62 20 22 6e 74 64 6c 6c 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 22 } //01 00  Lib "ntdll.dll" Alias "NtAllocateVirtualMemory"
		$a_00_1 = {4c 69 62 20 22 4e 74 64 6c 6c 2e 64 6c 6c 20 20 22 20 41 6c 69 61 73 20 22 5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 22 } //01 00  Lib "Ntdll.dll  " Alias "ZwWriteVirtualMemory"
		$a_00_2 = {22 53 68 6c 77 61 70 69 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 50 61 74 68 46 69 6c 65 45 78 69 73 74 73 22 } //01 00  "Shlwapi.dll" Alias "PathFileExists"
		$a_00_3 = {22 53 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 48 43 68 61 6e 67 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 5f 4c 6f 63 6b 22 } //01 00  "Shell32.dll" Alias "SHChangeNotification_Lock"
		$a_00_4 = {4c 69 62 20 22 53 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 48 47 65 74 44 65 73 6b 74 6f 70 46 6f 6c 64 65 72 22 } //01 00  Lib "Shell32.dll" Alias "SHGetDesktopFolder"
		$a_00_5 = {4c 69 62 20 22 53 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 48 47 65 74 53 65 74 74 69 6e 67 73 } //01 00  Lib "Shell32.dll" Alias "SHGetSettings
		$a_00_6 = {4c 69 62 20 22 4b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 52 65 61 64 43 6f 6e 73 6f 6c 65 57 22 } //01 00  Lib "Kernel32.dll" Alias "ReadConsoleW"
		$a_00_7 = {4c 69 62 20 22 55 73 65 72 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 47 72 61 79 53 74 72 69 6e 67 41 22 } //01 00  Lib "User32.dll" Alias "GrayStringA"
		$a_00_8 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e } //00 00  #If Win64 Then
	condition:
		any of ($a_*)
 
}