
rule Trojan_BAT_AgentTesla_CFM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {54 00 56 00 71 00 51 00 41 00 41 00 4d 00 41 00 41 00 41 00 41 00 45 00 41 00 41 00 41 00 41 00 2f 00 2f 00 38 00 41 00 41 00 4c 00 67 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 51 00 } //1 TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ
		$a_00_1 = {75 00 67 00 34 00 41 00 74 00 41 00 6e 00 4e 00 49 00 62 00 67 00 42 00 54 00 4d 00 30 00 68 00 } //1 ug4AtAnNIbgBTM0h
		$a_81_2 = {54 68 72 65 61 64 50 6f 6f 6c 2e 4c 69 67 68 74 } //1 ThreadPool.Light
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}