
rule Trojan_BAT_AgentTesla_FG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_81_0 = {48 6f 73 70 69 74 61 6c 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d } //10 HospitalManagementSystem
		$a_81_1 = {58 41 53 58 41 58 } //10 XASXAX
		$a_81_2 = {73 73 73 61 73 53 41 44 41 53 44 41 44 41 44 73 73 } //1 sssasSADASDADADss
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_5 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_6 = {67 65 74 5f 49 73 41 6c 69 76 65 } //1 get_IsAlive
		$a_81_7 = {43 6f 6e 76 65 72 74 } //1 Convert
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=16
 
}
rule Trojan_BAT_AgentTesla_FG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {49 4d 47 5f 90 02 0f 2e 67 2e 72 65 73 6f 75 72 63 65 73 90 00 } //20
		$a_03_1 = {43 6f 6e 73 6f 6c 65 41 70 70 90 02 0f 2e 67 2e 72 65 73 6f 75 72 63 65 73 90 00 } //20
		$a_03_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 90 02 0f 2e 67 2e 72 65 73 6f 75 72 63 65 73 90 00 } //20
		$a_03_3 = {4f 72 64 65 72 90 02 0f 2e 67 2e 72 65 73 6f 75 72 63 65 73 90 00 } //20
		$a_81_4 = {53 75 72 65 73 68 20 44 61 73 61 72 69 } //1 Suresh Dasari
		$a_81_5 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_03_6 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 33 90 02 0f 2d 31 90 00 } //1
		$a_81_7 = {42 65 67 69 6e 49 6e 76 6f 6b 65 } //1 BeginInvoke
		$a_81_8 = {52 65 73 6f 6c 76 65 4d 65 74 68 6f 64 } //1 ResolveMethod
		$a_81_9 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*20+(#a_03_2  & 1)*20+(#a_03_3  & 1)*20+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_03_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=26
 
}