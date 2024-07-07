
rule Trojan_BAT_AgentTesla_PTHG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 16 11 03 16 11 04 28 90 01 01 00 00 06 20 01 00 00 00 7e 07 08 00 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}