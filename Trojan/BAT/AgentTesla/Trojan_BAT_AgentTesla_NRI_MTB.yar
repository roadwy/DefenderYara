
rule Trojan_BAT_AgentTesla_NRI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 37 31 64 32 64 35 38 38 2d 30 61 35 34 2d 34 30 33 65 2d 62 65 32 35 2d 38 31 34 62 38 34 63 63 65 62 32 32 } //1 $71d2d588-0a54-403e-be25-814b84cceb22
		$a_01_1 = {4c 49 4c 49 54 48 41 47 55 45 53 54 48 4f 55 53 45 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 LILITHAGUESTHOUSE.Resources.resources
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}