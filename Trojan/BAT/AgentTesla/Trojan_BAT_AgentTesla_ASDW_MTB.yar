
rule Trojan_BAT_AgentTesla_ASDW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 00 11 11 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 0f 20 06 00 00 00 7e 90 01 01 02 00 04 7b 90 01 01 02 00 04 39 90 01 01 00 00 00 26 20 07 00 00 00 38 90 00 } //1
		$a_81_1 = {50 68 75 72 65 7a 6a 66 74 67 67 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Phurezjftgg.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}