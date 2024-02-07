
rule VirTool_BAT_Injector_DT_bit{
	meta:
		description = "VirTool:BAT/Injector.DT!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 6e 64 62 6f 78 41 72 74 69 66 61 63 74 73 50 72 65 73 65 6e 74 } //01 00  SandboxArtifactsPresent
		$a_01_1 = {43 72 65 61 74 65 53 74 61 72 74 75 70 53 68 6f 72 74 63 75 74 } //01 00  CreateStartupShortcut
		$a_01_2 = {52 75 6e 49 6e 4d 65 6d 6f 72 79 } //01 00  RunInMemory
		$a_01_3 = {53 70 61 77 6e 4e 65 77 50 72 6f 63 65 73 73 } //01 00  SpawnNewProcess
		$a_01_4 = {52 65 63 6c 61 69 6d 4d 75 74 65 78 } //01 00  ReclaimMutex
		$a_01_5 = {4d 6f 6e 69 74 6f 72 53 70 61 77 6e 6c 69 6e 67 } //01 00  MonitorSpawnling
		$a_01_6 = {61 6e 74 69 56 4d 53 } //01 00  antiVMS
		$a_01_7 = {4d 6f 6e 69 74 6f 72 50 61 63 6b 61 67 65 48 6f 73 74 } //00 00  MonitorPackageHost
	condition:
		any of ($a_*)
 
}