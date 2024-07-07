
rule Trojan_BAT_AgentTesla_RDBN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 6f b3 00 00 0a 0d 09 6f b4 00 00 0a 18 9a 13 04 11 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}