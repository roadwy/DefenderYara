
rule Trojan_BAT_AgentTesla_BKC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 fe 01 00 0a 28 18 02 00 06 28 16 02 00 06 28 17 02 00 06 28 39 00 00 0a 28 19 02 00 06 fe 0e 00 00 fe 0c 00 00 72 d3 08 00 70 6f 58 00 00 0a 39 17 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}