
rule Backdoor_BAT_Rescoms_AA_bit{
	meta:
		description = "Backdoor:BAT/Rescoms.AA!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 70 61 77 6e 4e 65 77 50 72 6f 63 65 73 73 } //1 SpawnNewProcess
		$a_01_1 = {53 65 74 48 69 64 64 65 6e } //1 SetHidden
		$a_01_2 = {44 6f 77 6e 45 78 65 63 } //1 DownExec
		$a_01_3 = {44 65 74 65 63 74 56 6d } //1 DetectVm
		$a_01_4 = {4d 6f 6e 69 74 6f 72 69 6e 67 53 65 6c 66 } //1 MonitoringSelf
		$a_01_5 = {52 75 6e 50 65 72 73 69 73 74 65 6e 63 65 } //1 RunPersistence
		$a_01_6 = {52 65 63 6c 61 69 6d 4d 75 74 65 78 } //1 ReclaimMutex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}