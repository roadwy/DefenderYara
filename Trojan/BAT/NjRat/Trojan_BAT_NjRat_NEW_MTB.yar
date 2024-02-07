
rule Trojan_BAT_NjRat_NEW_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 07 00 "
		
	strings :
		$a_01_0 = {11 0d 28 2c 00 00 0a 13 0f 1f 12 38 7f fd ff ff 11 04 7b 09 00 00 04 11 08 1e d6 11 0f 1a 12 01 28 16 00 00 06 2d 06 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 } //01 00  CreateProcess
		$a_01_2 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  GetThreadContext
		$a_01_3 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_01_4 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  NtUnmapViewOfSection
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //01 00  VirtualAllocEx
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_7 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //00 00  ResumeThread
	condition:
		any of ($a_*)
 
}