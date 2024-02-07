
rule VirTool_Win32_Obfuscator_CE{
	meta:
		description = "VirTool:Win32/Obfuscator.CE,SIGNATURE_TYPE_PEHSTR_EXT,ffffff94 01 ffffff94 01 07 00 00 ffffffc8 00 "
		
	strings :
		$a_00_0 = {8b c3 99 03 45 e0 13 55 e4 33 04 24 33 54 24 04 83 c4 08 5a 88 02 43 46 4f 75 } //c8 00 
		$a_00_1 = {8a 98 00 01 00 00 02 14 18 81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75 } //01 00 
		$a_00_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //01 00  VirtualAllocEx
		$a_00_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //01 00  VirtualProtectEx
		$a_00_4 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  ZwUnmapViewOfSection
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_6 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
	condition:
		any of ($a_*)
 
}