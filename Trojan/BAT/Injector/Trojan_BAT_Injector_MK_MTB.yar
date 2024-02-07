
rule Trojan_BAT_Injector_MK_MTB{
	meta:
		description = "Trojan:BAT/Injector.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 73 75 6d 65 54 68 72 65 61 64 5f 41 50 49 } //01 00  ResumeThread_API
		$a_01_1 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 5f 41 50 49 } //01 00  NtUnmapViewOfSection_API
		$a_01_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 5f 41 50 49 } //01 00  CreateProcess_API
		$a_01_3 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 5f 41 50 49 } //01 00  Wow64GetThreadContext_API
		$a_01_4 = {57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 5f 41 50 49 } //01 00  Wow64SetThreadContext_API
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 5f 41 50 49 } //01 00  VirtualAllocEx_API
		$a_01_6 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 5f 41 50 49 } //01 00  ReadProcessMemory_API
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 5f 41 50 49 } //01 00  WriteProcessMemory_API
		$a_01_8 = {53 54 41 52 54 55 50 5f 49 4e 46 4f 52 4d 41 54 49 4f 4e } //01 00  STARTUP_INFORMATION
		$a_01_9 = {50 52 4f 43 45 53 53 5f 49 4e 46 4f 52 4d 41 54 49 4f 4e } //01 00  PROCESS_INFORMATION
		$a_01_10 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_01_11 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //01 00  HideModuleNameAttribute
		$a_01_12 = {4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c 69 61 74 68 } //01 00  ObfuscatedByGoliath
		$a_01_13 = {4e 69 6e 65 52 61 79 73 2e 4f 62 66 75 73 63 61 74 6f 72 2e 45 76 61 6c 75 61 74 69 6f 6e } //01 00  NineRays.Obfuscator.Evaluation
		$a_01_14 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //01 00  get_WebServices
		$a_01_15 = {67 65 74 5f 53 65 74 74 69 6e 67 73 } //01 00  get_Settings
		$a_01_16 = {67 65 74 5f 43 6f 6e 74 72 6f 6c 73 } //01 00  get_Controls
		$a_01_17 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}