
rule Trojan_BAT_AgentTesla_PTHS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 4b 00 00 01 25 17 73 20 00 00 0a 13 04 06 6f 21 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}