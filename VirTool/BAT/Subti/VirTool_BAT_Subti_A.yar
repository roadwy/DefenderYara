
rule VirTool_BAT_Subti_A{
	meta:
		description = "VirTool:BAT/Subti.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_1 = {52 65 6d 6f 76 65 5a 49 44 } //01 00  RemoveZID
		$a_01_2 = {56 4d 46 6f 75 6e 64 } //01 00  VMFound
		$a_01_3 = {53 61 6e 64 62 6f 78 46 6f 75 6e 64 } //01 00  SandboxFound
		$a_01_4 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_01_5 = {43 6f 6d 70 69 6c 65 41 6e 64 52 75 6e } //01 00  CompileAndRun
		$a_01_6 = {41 64 64 54 6f 53 74 61 72 74 75 70 } //01 00  AddToStartup
		$a_01_7 = {52 75 6e 50 45 } //01 00  RunPE
		$a_01_8 = {42 61 63 6b 75 70 52 75 6e } //01 00  BackupRun
		$a_01_9 = {52 75 6e 4e 65 74 } //00 00  RunNet
		$a_01_10 = {00 61 aa 00 } //00 07 
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_Subti_A_2{
	meta:
		description = "VirTool:BAT/Subti.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 65 78 65 63 75 74 69 6f 6e } //01 00  _execution
		$a_01_1 = {5f 69 73 44 6f 74 4e 65 74 } //01 00  _isDotNet
		$a_01_2 = {5f 6d 65 6c 74 } //01 00  _melt
		$a_01_3 = {5f 68 69 64 65 } //01 00  _hide
		$a_01_4 = {5f 66 61 6b 65 4d 65 73 73 61 67 65 } //01 00  _fakeMessage
		$a_01_5 = {5f 70 72 6f 63 65 73 73 50 65 72 73 69 73 74 65 6e 63 65 } //01 00  _processPersistence
		$a_01_6 = {5f 61 6e 74 69 56 6d } //01 00  _antiVm
		$a_01_7 = {5f 61 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //01 00  _antiSandboxie
		$a_01_8 = {5f 73 74 61 72 74 55 70 50 65 72 73 69 73 74 65 6e 63 65 } //01 00  _startUpPersistence
		$a_01_9 = {5f 62 69 6e 64 65 72 52 75 6e 46 69 72 73 74 } //01 00  _binderRunFirst
		$a_01_10 = {5f 64 6f 77 6e 6c 6f 61 64 65 72 } //00 00  _downloader
		$a_01_11 = {00 5d 04 00 } //00 a6 
	condition:
		any of ($a_*)
 
}