
rule Trojan_BAT_AgentTesla_ABJJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 03 06 9c 90 00 } //2
		$a_01_1 = {52 00 65 00 6c 00 61 00 79 00 2e 00 47 00 52 00 45 00 45 00 4e } //2
		$a_01_2 = {52 00 65 00 6c 00 61 00 79 00 2e 00 47 00 52 00 45 00 45 00 4e 00 } //2 Relay.GREEN
		$a_01_3 = {52 00 65 00 6c 00 61 00 79 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Relay.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}