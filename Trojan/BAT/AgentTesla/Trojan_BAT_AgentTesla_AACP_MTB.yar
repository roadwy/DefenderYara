
rule Trojan_BAT_AgentTesla_AACP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AACP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 1e 11 20 58 11 1f 11 21 58 6f 90 01 01 00 00 0a 13 22 12 22 28 90 01 01 00 00 0a 13 23 07 09 11 23 9c 09 17 58 0d 00 11 21 17 58 13 21 11 21 17 fe 04 13 24 11 24 2d c9 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}