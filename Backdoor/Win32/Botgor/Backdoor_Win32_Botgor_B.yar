
rule Backdoor_Win32_Botgor_B{
	meta:
		description = "Backdoor:Win32/Botgor.B,SIGNATURE_TYPE_PEHSTR_EXT,57 00 56 00 0a 00 00 14 00 "
		
	strings :
		$a_00_0 = {43 61 6e 6e 6f 74 20 65 78 65 63 75 74 65 20 70 72 6f 67 72 61 6d 21 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 77 69 6c 6c 20 62 65 20 74 65 72 6d 69 6e 61 74 65 64 } //14 00  Cannot execute program! Application will be terminated
		$a_00_1 = {64 61 74 61 66 69 6c 65 31 } //14 00  datafile1
		$a_00_2 = {00 20 2d 63 75 72 65 00 } //14 00 
		$a_00_3 = {00 62 6f 74 31 2e 65 78 65 } //01 00 
		$a_00_4 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  ZwUnmapViewOfSection
		$a_00_5 = {49 73 42 61 64 52 65 61 64 50 74 72 28 29 } //01 00  IsBadReadPtr()
		$a_00_6 = {21 43 72 65 61 74 65 50 72 6f 63 65 73 73 28 29 } //03 00  !CreateProcess()
		$a_00_7 = {43 3a 5c 4d 79 52 65 70 2e 64 61 74 } //03 00  C:\MyRep.dat
		$a_01_8 = {22 4d 41 49 4e 5f 45 58 45 22 } //03 00  "MAIN_EXE"
		$a_01_9 = {c7 45 f4 b9 79 37 9e c7 45 ec 20 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}