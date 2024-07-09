
rule Trojan_BAT_AgentTesla_ABXG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 43 00 16 13 04 2b 28 00 08 09 11 04 6f ?? 00 00 0a 13 0b 12 0b 28 ?? 00 00 0a 13 0c 07 11 05 11 0c 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? 00 00 0a fe 04 13 0d 11 0d 2d c8 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}