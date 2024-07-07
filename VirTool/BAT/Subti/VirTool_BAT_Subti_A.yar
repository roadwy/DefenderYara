
rule VirTool_BAT_Subti_A{
	meta:
		description = "VirTool:BAT/Subti.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 0a 00 00 "
		
	strings :
		$a_01_0 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_1 = {52 65 6d 6f 76 65 5a 49 44 } //1 RemoveZID
		$a_01_2 = {56 4d 46 6f 75 6e 64 } //1 VMFound
		$a_01_3 = {53 61 6e 64 62 6f 78 46 6f 75 6e 64 } //1 SandboxFound
		$a_01_4 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_01_5 = {43 6f 6d 70 69 6c 65 41 6e 64 52 75 6e } //1 CompileAndRun
		$a_01_6 = {41 64 64 54 6f 53 74 61 72 74 75 70 } //1 AddToStartup
		$a_01_7 = {52 75 6e 50 45 } //1 RunPE
		$a_01_8 = {42 61 63 6b 75 70 52 75 6e } //1 BackupRun
		$a_01_9 = {52 75 6e 4e 65 74 } //1 RunNet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=7
 
}
rule VirTool_BAT_Subti_A_2{
	meta:
		description = "VirTool:BAT/Subti.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 0b 00 00 "
		
	strings :
		$a_01_0 = {5f 65 78 65 63 75 74 69 6f 6e } //1 _execution
		$a_01_1 = {5f 69 73 44 6f 74 4e 65 74 } //1 _isDotNet
		$a_01_2 = {5f 6d 65 6c 74 } //1 _melt
		$a_01_3 = {5f 68 69 64 65 } //1 _hide
		$a_01_4 = {5f 66 61 6b 65 4d 65 73 73 61 67 65 } //1 _fakeMessage
		$a_01_5 = {5f 70 72 6f 63 65 73 73 50 65 72 73 69 73 74 65 6e 63 65 } //1 _processPersistence
		$a_01_6 = {5f 61 6e 74 69 56 6d } //1 _antiVm
		$a_01_7 = {5f 61 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //1 _antiSandboxie
		$a_01_8 = {5f 73 74 61 72 74 55 70 50 65 72 73 69 73 74 65 6e 63 65 } //1 _startUpPersistence
		$a_01_9 = {5f 62 69 6e 64 65 72 52 75 6e 46 69 72 73 74 } //1 _binderRunFirst
		$a_01_10 = {5f 64 6f 77 6e 6c 6f 61 64 65 72 } //1 _downloader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=7
 
}