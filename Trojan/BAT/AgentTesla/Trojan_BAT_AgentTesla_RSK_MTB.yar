
rule Trojan_BAT_AgentTesla_RSK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {57 15 a2 09 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 5f 00 00 00 0f 00 00 00 96 00 00 00 41 00 00 00 43 00 00 00 94 00 00 00 16 00 00 00 0f 00 00 00 02 00 00 00 04 00 00 00 05 00 00 00 0a 00 00 00 01 00 00 00 05 00 00 00 0b } //1
		$a_81_1 = {50 65 72 73 6f 6e 6e 65 6c 54 72 61 63 6b 69 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 PersonnelTracking.Properties.Resources.resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}