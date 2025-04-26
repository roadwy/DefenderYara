
rule Trojan_BAT_AgentTesla_BAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 07 2b 1a 08 11 07 07 11 07 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d d9 } //1
		$a_01_1 = {46 00 6c 00 69 00 70 00 46 00 6c 00 6f 00 70 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 FlipFlop.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}