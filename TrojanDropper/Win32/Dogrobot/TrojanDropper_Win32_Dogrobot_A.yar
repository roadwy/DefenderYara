
rule TrojanDropper_Win32_Dogrobot_A{
	meta:
		description = "TrojanDropper:Win32/Dogrobot.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6d 64 20 2f 63 20 64 65 6c 20 } //01 00  cmd /c del 
		$a_00_1 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 33 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 5c 50 61 72 61 6d 65 74 65 72 73 } //01 00  SYSTEM\ControlSet003\Services\BITS\Parameters
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 5c 50 61 72 61 6d 65 74 65 72 73 } //01 00  SYSTEM\CurrentControlSet\Services\BITS\Parameters
		$a_01_3 = {53 65 72 76 69 63 65 44 6c 6c } //01 00  ServiceDll
		$a_00_4 = {73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //01 00  system32\rundll32.exe
		$a_01_5 = {20 68 65 6c 6c 6f } //01 00   hello
		$a_01_6 = {25 73 25 64 5f 72 65 73 2e 74 6d 70 } //01 00  %s%d_res.tmp
		$a_01_7 = {61 76 70 2e 65 78 65 } //01 00  avp.exe
		$a_01_8 = {54 45 53 54 5f 45 56 45 4e 54 } //01 00  TEST_EVENT
		$a_00_9 = {5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 36 00 39 00 35 00 33 00 45 00 41 00 36 00 30 00 2d 00 38 00 44 00 35 00 46 00 2d 00 34 00 35 00 32 00 39 00 2d 00 38 00 37 00 31 00 30 00 2d 00 34 00 32 00 46 00 38 00 45 00 44 00 33 00 45 00 38 00 43 00 44 00 41 00 } //01 00  \BaseNamedObjects\6953EA60-8D5F-4529-8710-42F8ED3E8CDA
		$a_00_10 = {57 69 6e 45 78 65 63 } //01 00  WinExec
		$a_00_11 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_00_12 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_00_13 = {43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 41 } //00 00  ChangeServiceConfigA
	condition:
		any of ($a_*)
 
}