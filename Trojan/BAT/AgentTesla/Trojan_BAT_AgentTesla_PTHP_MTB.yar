
rule Trojan_BAT_AgentTesla_PTHP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 f5 00 00 0a 13 05 2b 13 28 ?? 00 00 0a 11 11 16 11 11 8e 69 6f f8 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}