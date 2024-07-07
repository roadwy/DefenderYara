
rule Trojan_BAT_AgentTesla_AACI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AACI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 2e 11 0a 09 11 05 58 11 04 11 06 58 6f 90 01 01 00 00 0a 13 12 12 12 28 90 01 01 00 00 0a 13 0c 11 09 11 07 11 0c 9c 11 07 17 58 13 07 11 06 17 58 13 06 11 06 17 fe 04 13 0d 11 0d 2d c7 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}