
rule Trojan_BAT_AgentTesla_CI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 11 04 7e 89 01 00 04 1f 4b 7e 89 01 00 04 1f 4b 93 7e 89 01 00 04 20 8d 00 00 00 93 61 1f 17 5f 9d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}