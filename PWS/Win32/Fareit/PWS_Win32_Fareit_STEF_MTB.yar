
rule PWS_Win32_Fareit_STEF_MTB{
	meta:
		description = "PWS:Win32/Fareit.STEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 69 65 6e 52 75 6e 50 45 2e 41 6c 69 65 6e 52 75 6e 50 45 } //01 00  AlienRunPE.AlienRunPE
		$a_81_1 = {43 6f 6e 76 65 72 74 46 72 6f 6d 55 74 66 33 32 } //01 00  ConvertFromUtf32
		$a_81_2 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_3 = {57 72 69 74 65 42 79 74 65 } //01 00  WriteByte
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_81_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_6 = {53 74 72 69 6e 67 43 6f 6d 70 61 72 69 73 6f 6e } //01 00  StringComparison
		$a_81_7 = {50 6f 6f 6c 65 64 53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //01 00  PooledStringBuilder
		$a_81_8 = {4c 6f 6f 70 54 69 6d 65 72 } //01 00  LoopTimer
		$a_81_9 = {52 6f 73 6c 79 6e 2e 55 74 69 6c 69 74 69 65 73 } //01 00  Roslyn.Utilities
		$a_81_10 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_81_11 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_81_12 = {52 65 73 75 6d 65 4c 61 79 6f 75 74 } //01 00  ResumeLayout
		$a_81_13 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_81_14 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //00 00  RtlMoveMemory
	condition:
		any of ($a_*)
 
}