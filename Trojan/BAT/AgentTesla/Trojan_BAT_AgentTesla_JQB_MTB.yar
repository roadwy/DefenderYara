
rule Trojan_BAT_AgentTesla_JQB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {24 38 61 38 66 35 32 39 32 2d 38 32 33 63 2d 34 62 38 33 2d 39 62 31 35 2d 38 36 31 37 61 38 61 34 62 36 31 30 } //1 $8a8f5292-823c-4b83-9b15-8617a8a4b610
		$a_81_1 = {00 58 58 58 58 58 58 00 } //1 堀塘塘X
		$a_81_2 = {54 68 72 65 61 64 50 6f 6f 6c 2e 4c 69 67 68 74 } //1 ThreadPool.Light
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_4 = {41 63 74 69 6f 6e 5f 54 69 6d 65 72 } //1 Action_Timer
		$a_81_5 = {41 63 74 69 6f 6e 20 4c 69 73 74 2e 69 6e 69 } //1 Action List.ini
		$a_81_6 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}