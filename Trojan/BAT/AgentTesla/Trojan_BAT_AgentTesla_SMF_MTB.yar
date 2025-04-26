
rule Trojan_BAT_AgentTesla_SMF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {24 33 62 64 31 34 31 36 30 2d 66 30 62 37 2d 34 37 62 66 2d 38 33 66 39 2d 62 30 61 32 65 37 63 61 36 32 38 65 } //1 $3bd14160-f0b7-47bf-83f9-b0a2e7ca628e
		$a_81_1 = {48 61 64 6f 75 6b 65 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Hadouken.Properties.Resources.resources
		$a_81_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_3 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}