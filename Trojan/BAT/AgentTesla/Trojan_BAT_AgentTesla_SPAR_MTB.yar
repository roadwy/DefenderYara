
rule Trojan_BAT_AgentTesla_SPAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 02 08 91 03 08 06 5d 91 61 9c 08 17 d6 0c 08 09 31 ec } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}