
rule Trojan_BAT_AgentTesla_ABQA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 0a 9a 13 0e 11 09 11 0e 1f 10 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 00 11 0a 17 d6 13 0a 00 11 0a 11 08 8e 69 fe 04 13 0f 11 0f 2d d2 } //5
		$a_01_1 = {50 00 69 00 6e 00 67 00 47 00 72 00 61 00 70 00 68 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 PingGraph.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}