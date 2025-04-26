
rule Trojan_BAT_AgentTesla_GFQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 24 9d 6f ?? ?? ?? 0a 0b 07 8e 69 8d 56 00 00 01 0c 16 13 04 2b 17 00 08 11 04 07 11 04 9a 1f 10 28 ?? ?? ?? 0a 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dc } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}