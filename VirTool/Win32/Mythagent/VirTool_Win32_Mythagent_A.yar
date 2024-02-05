
rule VirTool_Win32_Mythagent_A{
	meta:
		description = "VirTool:Win32/Mythagent.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 65 6c 66 2e 67 65 74 54 61 73 6b 69 6e 67 73 28 } //self.getTaskings(  01 00 
		$a_80_1 = {73 65 6c 66 2e 70 72 6f 63 65 73 73 54 61 73 6b 69 6e 67 73 28 } //self.processTaskings(  01 00 
		$a_80_2 = {73 65 6c 66 2e 70 6f 73 74 52 65 73 70 6f 6e 73 65 73 28 } //self.postResponses(  01 00 
		$a_80_3 = {73 65 6c 66 2e 61 67 65 6e 74 5f 63 6f 6e 66 69 67 } //self.agent_config  01 00 
		$a_80_4 = {22 4a 69 74 74 65 72 22 3a } //"Jitter":  01 00 
		$a_80_5 = {22 50 61 79 6c 6f 61 64 55 55 49 44 22 3a } //"PayloadUUID":  01 00 
		$a_80_6 = {74 61 73 6b 5b 22 74 61 73 6b 5f 69 64 22 5d } //task["task_id"]  01 00 
		$a_80_7 = {66 69 6c 65 5f 62 72 6f 77 73 65 72 5b 22 66 69 6c 65 73 22 5d } //file_browser["files"]  01 00 
		$a_80_8 = {73 65 6c 66 2e 70 6f 73 74 4d 65 73 73 61 67 65 41 6e 64 52 65 74 72 69 65 76 65 52 65 73 70 6f 6e 73 65 } //self.postMessageAndRetrieveResponse  01 00 
		$a_80_9 = {2e 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 28 } //.CreateRemoteThread(  01 00 
		$a_80_10 = {70 61 73 73 65 64 4b 69 6c 6c 64 61 74 65 28 } //passedKilldate(  01 00 
		$a_80_11 = {22 50 72 6f 78 79 48 6f 73 74 22 3a } //"ProxyHost":  01 00 
		$a_80_12 = {73 65 6c 66 2e 61 67 65 6e 74 53 6c 65 65 70 28 29 } //self.agentSleep()  00 00 
	condition:
		any of ($a_*)
 
}