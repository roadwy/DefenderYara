
rule Trojan_BAT_AgentTesla_PSQG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 73 f0 01 00 06 7d 23 00 00 04 38 00 00 00 00 02 14 7d 25 00 00 04 38 00 00 00 00 02 28 10 00 00 0a 20 00 00 00 00 17 3a 0f 00 00 00 26 38 05 00 00 00 38 be ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}