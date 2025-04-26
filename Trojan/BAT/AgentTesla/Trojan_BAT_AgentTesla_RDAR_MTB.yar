
rule Trojan_BAT_AgentTesla_RDAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 20 5d 17 58 13 04 11 04 59 20 80 00 00 00 58 20 80 00 00 00 5d d1 13 05 06 11 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}