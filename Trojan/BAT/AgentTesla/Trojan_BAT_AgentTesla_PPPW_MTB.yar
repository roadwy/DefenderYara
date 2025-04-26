
rule Trojan_BAT_AgentTesla_PPPW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PPPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 08 09 6f ?? 00 00 0a 13 05 73 63 00 00 0a 13 06 11 06 11 05 17 73 64 00 00 0a 13 07 11 07 06 16 06 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 0a dd 0f 00 00 00 11 07 39 07 00 00 00 11 07 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}