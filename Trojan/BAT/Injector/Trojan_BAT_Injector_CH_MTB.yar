
rule Trojan_BAT_Injector_CH_MTB{
	meta:
		description = "Trojan:BAT/Injector.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 19 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6e 50 65 } //01 00  RunPe
		$a_01_1 = {50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  ProcessInformation
		$a_01_2 = {53 74 61 72 74 75 70 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  StartupInformation
		$a_01_3 = {3c 4d 6f 64 75 6c 65 3e } //01 00  <Module>
		$a_01_4 = {3c 50 72 69 76 61 74 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 3e } //01 00  <PrivateImplementationDetails>
		$a_01_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_01_6 = {49 6e 74 50 74 72 } //01 00  IntPtr
		$a_01_7 = {55 49 6e 74 33 32 } //01 00  UInt32
		$a_01_8 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 } //01 00  CreateProcess
		$a_01_9 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  GetThreadContext
		$a_01_10 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  Wow64GetThreadContext
		$a_01_11 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  SetThreadContext
		$a_01_12 = {57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  Wow64SetThreadContext
		$a_01_13 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_01_14 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_15 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  NtUnmapViewOfSection
		$a_01_16 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //01 00  VirtualAllocEx
		$a_01_17 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //01 00  ResumeThread
		$a_01_18 = {54 6f 49 6e 74 33 32 } //01 00  ToInt32
		$a_01_19 = {54 6f 49 6e 74 31 36 } //01 00  ToInt16
		$a_01_20 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_21 = {42 75 66 66 65 72 } //01 00  Buffer
		$a_01_22 = {42 6c 6f 63 6b 43 6f 70 79 } //01 00  BlockCopy
		$a_01_23 = {50 72 6f 63 65 73 73 } //01 00  Process
		$a_01_24 = {47 65 74 50 72 6f 63 65 73 73 42 79 49 64 } //00 00  GetProcessById
	condition:
		any of ($a_*)
 
}