
rule Trojan_BAT_AgentTesla_RDBL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 12 08 28 17 00 00 0a 11 05 11 04 11 06 18 6f 18 00 00 0a 1f 10 28 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}