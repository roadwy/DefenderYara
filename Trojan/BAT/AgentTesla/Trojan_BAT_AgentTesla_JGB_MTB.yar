
rule Trojan_BAT_AgentTesla_JGB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_81_1 = {4c 7a 6d 77 41 71 6d 56 2e 65 78 65 } //01 00  LzmwAqmV.exe
		$a_81_2 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //01 00  WriteAllBytes
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 50 61 79 6c 6f 61 64 } //01 00  DownloadPayload
		$a_81_4 = {43 6f 6d 62 69 6e 65 } //01 00  Combine
		$a_81_5 = {45 78 65 63 75 74 65 } //01 00  Execute
		$a_81_6 = {52 75 6e 4f 6e 53 74 61 72 74 75 70 } //01 00  RunOnStartup
		$a_81_7 = {43 68 65 63 6b 45 6d 75 6c 61 74 6f 72 } //01 00  CheckEmulator
		$a_81_8 = {44 65 74 65 63 74 56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 } //01 00  DetectVirtualMachine
		$a_81_9 = {50 72 6f 67 72 61 6d } //01 00  Program
		$a_81_10 = {47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 } //01 00  GetEntryAssembly
		$a_81_11 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_81_12 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 } //01 00  GetModuleHandle
		$a_81_13 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //00 00  SbieDll.dll
	condition:
		any of ($a_*)
 
}