
rule Trojan_BAT_AgentTesla_GPE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {61 6c 6c 73 74 61 72 70 72 69 76 61 74 65 2e 6e 65 74 } //1 allstarprivate.net
		$a_01_1 = {00 44 6f 77 6e 6c 6f 61 64 50 61 79 6c 6f 61 64 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}