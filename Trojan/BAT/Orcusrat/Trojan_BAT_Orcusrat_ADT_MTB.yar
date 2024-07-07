
rule Trojan_BAT_Orcusrat_ADT_MTB{
	meta:
		description = "Trojan:BAT/Orcusrat.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0f 00 0a 00 00 "
		
	strings :
		$a_80_0 = {4f 72 63 75 73 } //Orcus  4
		$a_80_1 = {4b 69 6c 6c 42 75 74 74 6f 6e 5f 43 6c 69 63 6b } //KillButton_Click  4
		$a_80_2 = {67 65 74 5f 4b 65 79 4c 6f 67 67 65 72 53 65 72 76 69 63 65 } //get_KeyLoggerService  4
		$a_80_3 = {54 61 6b 65 53 63 72 65 65 6e 73 68 6f 74 } //TakeScreenshot  4
		$a_80_4 = {5f 6b 65 79 62 6f 61 72 64 48 6f 6f 6b 48 61 6e 64 6c 65 } //_keyboardHookHandle  4
		$a_80_5 = {67 65 74 5f 49 63 6d 70 53 6f 63 6b 65 74 73 } //get_IcmpSockets  3
		$a_80_6 = {49 73 41 54 63 70 41 6e 61 79 6c 7a 65 72 52 75 6e 6e 69 6e 67 } //IsATcpAnaylzerRunning  3
		$a_80_7 = {73 65 74 5f 41 6e 74 69 56 4d 73 } //set_AntiVMs  3
		$a_80_8 = {73 65 74 5f 41 6e 74 69 44 65 62 75 67 67 65 72 } //set_AntiDebugger  3
		$a_80_9 = {73 65 74 5f 54 61 73 6b 53 63 68 65 64 75 6c 65 72 54 61 73 6b 4e 61 6d 65 } //set_TaskSchedulerTaskName  3
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3+(#a_80_9  & 1)*3) >=15
 
}