
rule Trojan_BAT_AgentTesla_ABJQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 64 00 7a 00 69 00 61 00 6c 00 79 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 00 49 41 00 73 00 68 00 6c 00 65 00 79 00 5f 00 4e 00 69 00 63 00 6f 00 6c 00 65 00 5f 00 5f 00 31 00 30 00 37 00 5f 00 4e 00 75 00 64 00 65 00 5f 00 50 00 68 00 6f 00 74 00 6f 00 73 00 5f 00 5f 00 5f 00 36 00 34 00 5f 00 00 47 44 00 65 00 61 00 6e 00 6e 00 61 00 5f 00 42 00 72 00 6f 00 6f 00 6b 00 73 00 5f 00 } //4 podzialy.Resources䤀Ashley_Nicole__107_Nude_Photos___64_䜀Deanna_Brooks_
		$a_01_1 = {70 00 6f 00 64 00 7a 00 69 00 61 00 6c 00 79 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 podzialy.Resources
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}