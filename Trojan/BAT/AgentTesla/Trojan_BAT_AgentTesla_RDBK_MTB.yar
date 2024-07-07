
rule Trojan_BAT_AgentTesla_RDBK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 09 5d 13 0d 11 07 11 06 91 11 0c 61 13 0e 11 07 11 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}