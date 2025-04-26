
rule Trojan_BAT_AgentTesla_AACU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AACU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 29 11 06 06 08 58 07 09 58 6f ?? 00 00 0a 13 0f 12 0f 28 ?? 00 00 0a 13 09 11 05 11 04 11 09 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0a 11 0a 2d cd } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}