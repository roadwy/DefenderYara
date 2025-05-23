
rule Backdoor_BAT_CobaltStrikeLoader_F_MTB{
	meta:
		description = "Backdoor:BAT/CobaltStrikeLoader.F!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 2e 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 Schedule.Service
		$a_01_1 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 } //1 Connect
		$a_01_2 = {47 00 65 00 74 00 46 00 6f 00 6c 00 64 00 65 00 72 00 } //1 GetFolder
		$a_01_3 = {47 00 65 00 74 00 54 00 61 00 73 00 6b 00 73 00 } //1 GetTasks
		$a_01_4 = {48 00 69 00 64 00 64 00 65 00 6e 00 } //1 Hidden
		$a_01_5 = {44 00 69 00 73 00 61 00 6c 00 6c 00 6f 00 77 00 53 00 74 00 61 00 72 00 74 00 49 00 66 00 4f 00 6e 00 42 00 61 00 74 00 74 00 65 00 72 00 69 00 65 00 73 00 } //1 DisallowStartIfOnBatteries
		$a_01_6 = {52 00 75 00 6e 00 4f 00 6e 00 6c 00 79 00 49 00 66 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 41 00 76 00 61 00 69 00 6c 00 61 00 62 00 6c 00 65 00 } //1 RunOnlyIfNetworkAvailable
		$a_01_7 = {53 00 74 00 61 00 72 00 74 00 57 00 68 00 65 00 6e 00 41 00 76 00 61 00 69 00 6c 00 61 00 62 00 6c 00 65 00 } //1 StartWhenAvailable
		$a_01_8 = {4c 00 6f 00 67 00 6f 00 6e 00 54 00 79 00 70 00 65 00 } //1 LogonType
		$a_01_9 = {52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 54 00 61 00 73 00 6b 00 44 00 65 00 66 00 69 00 6e 00 69 00 74 00 69 00 6f 00 6e 00 } //1 RegisterTaskDefinition
		$a_01_10 = {44 00 65 00 6c 00 65 00 74 00 65 00 54 00 61 00 73 00 6b 00 } //1 DeleteTask
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}