
rule Trojan_BAT_AgentTesla_PSNN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 24 00 00 0a 7e 01 00 00 04 02 08 6f 25 00 00 0a 28 26 00 00 0a a5 01 00 00 1b 0b 11 07 20 3f 26 89 5a 5a 20 a3 54 2f df 61 38 5c ff ff ff d0 01 00 00 1b 28 18 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}