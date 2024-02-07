
rule Backdoor_Win32_Spesass_A_MTB{
	meta:
		description = "Backdoor:Win32/Spesass.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 66 69 6e 64 50 69 64 } //01 00  main.findPid
		$a_01_1 = {6d 61 69 6e 2e 73 65 74 53 69 6c 65 6e 74 50 72 6f 63 65 73 73 45 78 69 74 } //01 00  main.setSilentProcessExit
		$a_01_2 = {6d 61 69 6e 2e 73 65 74 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  main.setSeDebugPrivilege
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 69 6c 65 6e 74 50 72 6f 63 65 73 73 45 78 69 74 5c 6c 73 61 73 73 2e 65 78 65 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe
		$a_01_4 = {52 65 70 6f 72 74 69 6e 67 4d 6f 64 65 } //01 00  ReportingMode
		$a_01_5 = {44 75 6d 70 54 79 70 65 } //01 00  DumpType
		$a_01_6 = {4c 6f 63 61 6c 44 75 6d 70 46 6f 6c 64 65 72 } //01 00  LocalDumpFolder
		$a_01_7 = {47 6c 6f 62 61 6c 46 6c 61 67 } //00 00  GlobalFlag
	condition:
		any of ($a_*)
 
}