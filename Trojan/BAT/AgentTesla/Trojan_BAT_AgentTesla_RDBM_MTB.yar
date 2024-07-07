
rule Trojan_BAT_AgentTesla_RDBM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 26 11 00 6f 90 01 04 25 26 6f 90 01 04 25 26 13 08 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}