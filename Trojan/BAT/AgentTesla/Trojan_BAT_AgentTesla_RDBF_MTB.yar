
rule Trojan_BAT_AgentTesla_RDBF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 09 11 06 17 73 73 00 00 0a 13 04 11 04 02 16 02 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}