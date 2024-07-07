
rule Trojan_BAT_AgentTesla_MZO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MZO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 73 2f 00 00 0a 28 30 00 00 0a 74 23 00 00 01 0b 08 16 8c 24 00 00 01 07 6f 31 00 00 0a 17 da 8c 24 00 00 01 17 8c 24 00 00 01 12 03 12 02 28 32 00 00 0a 39 27 00 00 00 06 07 08 28 33 00 00 0a 16 6f 34 00 00 0a 13 04 12 04 28 35 00 00 0a 6f 36 00 00 0a 08 09 12 02 28 37 00 00 0a 2d d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}