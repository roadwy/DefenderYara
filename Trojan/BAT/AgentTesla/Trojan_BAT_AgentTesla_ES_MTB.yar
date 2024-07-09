
rule Trojan_BAT_AgentTesla_ES_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {0a 18 5b 0a 73 ?? ?? ?? 0a 0b 16 0c 2b 1e 00 07 02 08 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 08 17 58 0c 08 06 fe 04 0d 09 2d da 07 6f ?? ?? ?? 0a 13 04 2b 00 11 04 2a } //10
		$a_81_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_3 = {43 6c 69 63 6b } //1 Click
		$a_81_4 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}
rule Trojan_BAT_AgentTesla_ES_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 08 00 00 "
		
	strings :
		$a_81_0 = {24 66 38 39 64 65 33 39 34 2d 36 64 63 36 2d 34 35 38 33 2d 38 38 31 30 2d 61 61 65 35 64 63 63 31 35 31 32 35 } //20 $f89de394-6dc6-4583-8810-aae5dcc15125
		$a_81_1 = {59 54 47 65 74 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //20 YTGet.My.Resources
		$a_81_2 = {59 54 47 65 74 2e 72 75 6c 65 65 64 69 74 6f 72 2e 72 65 73 6f 75 72 63 65 73 } //1 YTGet.ruleeditor.resources
		$a_81_3 = {53 61 76 2d 41 2d 43 65 6e 74 65 72 } //1 Sav-A-Center
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=25
 
}