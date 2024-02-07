
rule Trojan_Win32_Small_KJ{
	meta:
		description = "Trojan:Win32/Small.KJ,SIGNATURE_TYPE_PEHSTR_EXT,30 01 30 01 07 00 00 64 00 "
		
	strings :
		$a_02_0 = {55 89 e5 8b 45 0c 83 f8 01 75 28 8b 45 08 a3 90 01 02 40 00 e8 23 05 00 00 a1 90 01 02 40 00 09 c0 74 0b ff 35 90 01 02 40 00 e8 90 01 02 00 00 b8 01 00 00 00 eb 13 83 f8 00 75 0c e8 90 01 02 00 00 b8 01 00 00 00 eb 02 31 c0 c9 c2 0c 00 90 00 } //64 00 
		$a_02_1 = {55 89 e5 83 ec 08 56 8d 75 f8 56 6a 08 68 90 01 02 40 00 ff 35 90 01 02 40 00 6a ff ff 15 90 01 02 40 00 68 90 01 02 40 00 ff 15 90 01 02 40 00 68 90 01 02 40 00 50 ff 15 90 01 02 40 00 a3 90 01 02 40 00 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 90 01 02 40 00 89 45 fc 56 6a 06 68 90 01 02 40 00 ff 35 90 01 02 40 00 6a ff ff 15 90 01 02 40 00 5e 8b 45 fc c9 c2 18 00 90 00 } //64 00 
		$a_01_2 = {53 59 53 48 4f 53 54 2e 44 4c 4c } //01 00  SYSHOST.DLL
		$a_00_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_01_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_6 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  ReadProcessMemory
	condition:
		any of ($a_*)
 
}