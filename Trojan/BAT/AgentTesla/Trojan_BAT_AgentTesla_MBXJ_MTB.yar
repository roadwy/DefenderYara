
rule Trojan_BAT_AgentTesla_MBXJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 00 4b 00 38 00 45 00 38 00 4f 00 35 00 34 00 37 00 47 00 53 00 38 00 35 00 46 00 38 00 48 00 45 00 35 00 35 00 5a 00 48 00 43 00 } //2 DK8E8O547GS85F8HE55ZHC
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}