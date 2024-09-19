
rule Trojan_BAT_AgentTesla_RDCD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 6f 42 00 00 0a 8e 69 5d 91 61 d2 9c 00 06 17 58 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}