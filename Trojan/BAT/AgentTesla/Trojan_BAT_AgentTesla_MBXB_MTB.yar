
rule Trojan_BAT_AgentTesla_MBXB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 61 00 64 00 00 03 3a 00 00 05 41 00 41 00 00 29 49 00 6e 00 76 00 65 00 6e 00 74 00 6f 00 72 00 79 00 4d 00 61 00 69 00 6e 00 74 00 65 00 6e 00 61 00 6e 00 63 00 65 } //8
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=10
 
}