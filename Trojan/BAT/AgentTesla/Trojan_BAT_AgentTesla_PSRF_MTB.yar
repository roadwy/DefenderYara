
rule Trojan_BAT_AgentTesla_PSRF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 17 00 00 06 72 56 96 01 70 72 5c 96 01 70 6f 42 00 00 0a 0a 06 72 60 96 01 70 72 64 96 01 70 6f 42 00 00 0a 0a 06 6f 43 00 00 0a 18 5b 8d 4f 00 00 01 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}