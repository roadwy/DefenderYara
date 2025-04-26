
rule Trojan_BAT_AgentTesla_IC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {54 77 69 74 44 75 65 6c 2e 55 49 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TwitDuel.UI.Properties.Resources.resources
		$a_81_1 = {73 65 74 5f 54 77 69 74 74 65 72 43 6c 69 65 6e 74 55 72 6c } //1 set_TwitterClientUrl
		$a_81_2 = {6c 31 6c 69 6c 6c 69 49 69 6c 69 6c 49 } //1 l1lilliIililI
		$a_81_3 = {62 39 34 38 77 6d 68 6e 79 33 67 34 72 61 6b 61 6a 36 65 67 76 67 38 70 77 62 66 35 74 6b 35 35 } //1 b948wmhny3g4rakaj6egvg8pwbf5tk55
		$a_81_4 = {79 67 6d 75 33 72 39 76 65 65 6a 77 6a 68 37 6a 61 32 70 70 32 6e 79 78 6b 39 32 37 73 75 79 6c } //1 ygmu3r9veejwjh7ja2pp2nyxk927suyl
		$a_81_5 = {59 65 64 64 61 2e 54 77 69 74 74 65 72 } //1 Yedda.Twitter
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_8 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule Trojan_BAT_AgentTesla_IC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.IC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_1 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_6 = {00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 } //1 砀硸硸硸硸硸硸硸硸x
		$a_81_7 = {69 6d 69 6d 69 6d 69 6d 69 6d } //1 imimimimim
		$a_81_8 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
		$a_81_9 = {47 65 74 46 69 6c 65 4e 61 6d 65 42 79 55 52 4c } //1 GetFileNameByURL
		$a_81_10 = {42 56 49 50 4d 5f 4c 6f 63 61 6c } //1 BVIPM_Local
		$a_81_11 = {49 45 78 70 61 6e 64 6f 2e 50 6c 75 67 } //1 IExpando.Plug
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}