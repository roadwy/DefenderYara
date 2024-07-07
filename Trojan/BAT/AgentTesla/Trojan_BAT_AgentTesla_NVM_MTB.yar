
rule Trojan_BAT_AgentTesla_NVM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 38 4a 38 48 48 42 44 35 35 43 38 38 43 37 35 32 46 34 4e 45 47 } //10 H8J8HHBD55C88C752F4NEG
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_3 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}