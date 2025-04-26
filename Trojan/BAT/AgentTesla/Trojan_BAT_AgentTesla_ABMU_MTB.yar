
rule Trojan_BAT_AgentTesla_ABMU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 0a 11 05 11 0a 9a 1f 10 28 ?? ?? ?? 0a 9c 00 11 0a 17 58 13 0a 11 0a 11 05 8e 69 fe 04 13 0b 11 0b 2d d9 } //5
		$a_01_1 = {50 00 72 00 69 00 63 00 65 00 41 00 6e 00 64 00 47 00 72 00 61 00 70 00 68 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 PriceAndGraph.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}