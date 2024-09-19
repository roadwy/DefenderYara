
rule Trojan_BAT_AgentTesla_RDBQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 91 0d 07 08 91 09 61 07 08 17 58 07 8e 69 5d 91 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}