
rule Trojan_BAT_AgentTesla_PTKC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 cc 00 00 0a 25 80 2c 00 00 04 28 05 00 00 2b 28 06 00 00 2b 0c 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}