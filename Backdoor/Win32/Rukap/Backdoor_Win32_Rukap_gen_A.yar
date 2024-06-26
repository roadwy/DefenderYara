
rule Backdoor_Win32_Rukap_gen_A{
	meta:
		description = "Backdoor:Win32/Rukap.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,39 01 2c 01 14 00 00 64 00 "
		
	strings :
		$a_02_0 = {6a 01 6a 00 6a 00 6a 00 68 90 01 04 ff d6 85 c0 74 55 53 8b 1d 90 01 04 55 8b 2d 90 01 04 57 8b 3d 90 01 04 68 90 01 04 ff d7 68 90 01 04 ff d3 a1 90 00 } //64 00 
		$a_02_1 = {3d b7 00 00 00 75 0e 56 ff 15 90 01 04 6a 00 e8 90 01 04 33 c0 5e 90 00 } //01 00 
		$a_00_2 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_00_3 = {47 65 74 4c 61 73 74 45 72 72 6f 72 } //01 00  GetLastError
		$a_00_4 = {43 6c 6f 73 65 48 61 6e 64 6c 65 } //64 00  CloseHandle
		$a_02_5 = {52 6a 04 50 56 e8 90 01 04 85 c0 74 3b 8b 54 24 1c 8d 4c 24 20 68 04 01 00 00 51 52 56 e8 90 01 04 8b 84 24 28 11 00 00 8d 4c 24 20 50 51 e8 90 01 04 83 c4 08 85 c0 75 0d 50 56 90 00 } //01 00 
		$a_00_6 = {45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73 } //01 00  EnumProcessModules
		$a_00_7 = {47 65 74 4d 6f 64 75 6c 65 42 61 73 65 4e 61 6d 65 41 } //01 00  GetModuleBaseNameA
		$a_00_8 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //01 00  TerminateProcess
		$a_00_9 = {43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 41 } //01 00  ChangeServiceConfigA
		$a_00_10 = {49 6e 74 65 72 6e 65 74 57 72 69 74 65 46 69 6c 65 } //01 00  InternetWriteFile
		$a_01_11 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_00_12 = {43 72 65 61 74 65 53 65 72 76 69 63 65 41 } //01 00  CreateServiceA
		$a_00_13 = {52 65 67 43 72 65 61 74 65 4b 65 79 45 78 41 } //01 00  RegCreateKeyExA
		$a_00_14 = {52 65 67 44 65 6c 65 74 65 56 61 6c 75 65 41 } //01 00  RegDeleteValueA
		$a_00_15 = {52 61 73 45 6e 75 6d 43 6f 6e 6e 65 63 74 69 6f 6e 73 41 } //01 00  RasEnumConnectionsA
		$a_00_16 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 } //01 00  RegisterServiceProcess
		$a_00_17 = {57 53 32 5f 33 32 2e 44 4c 4c } //0c 00  WS2_32.DLL
		$a_01_18 = {da 40 83 f8 20 88 1c 31 75 02 33 c0 41 3b cf 72 e5 } //02 00 
		$a_01_19 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 69 72 65 63 74 } //00 00  Software\Microsoft\Direct
	condition:
		any of ($a_*)
 
}