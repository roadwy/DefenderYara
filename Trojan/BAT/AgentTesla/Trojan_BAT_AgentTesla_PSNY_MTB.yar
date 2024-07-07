
rule Trojan_BAT_AgentTesla_PSNY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 05 2b 13 28 64 00 00 0a 11 12 16 11 12 8e 69 6f 65 00 00 0a 13 05 11 0b 06 20 d3 ba 83 39 58 07 58 19 11 0b 5f 58 1b 62 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}