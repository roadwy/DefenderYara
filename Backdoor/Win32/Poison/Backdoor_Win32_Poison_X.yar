
rule Backdoor_Win32_Poison_X{
	meta:
		description = "Backdoor:Win32/Poison.X,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 5f 53 74 75 62 } //01 00  m_Stub
		$a_01_1 = {66 69 6c 65 2e 65 78 65 } //01 00  file.exe
		$a_01_2 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  NtUnmapViewOfSection
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_4 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //01 00  FindResourceA
		$a_01_5 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_6 = {6a 40 68 00 30 00 00 } //01 00 
		$a_01_7 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 } //01 00  jjѪjjj
		$a_01_8 = {81 fa 4d 5a 00 00 } //01 00 
		$a_01_9 = {81 3a 50 45 00 00 } //01 00 
		$a_01_10 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 } //00 00 
	condition:
		any of ($a_*)
 
}