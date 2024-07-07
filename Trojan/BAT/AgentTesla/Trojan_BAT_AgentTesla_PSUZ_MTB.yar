
rule Trojan_BAT_AgentTesla_PSUZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSUZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 67 00 00 06 14 fe 06 65 00 00 06 73 6f 00 00 06 80 14 00 00 04 7e 14 00 00 04 20 45 8c f5 f8 65 20 4f b6 2e fa 58 20 0a 2a 39 01 61 65 28 68 00 00 06 28 69 00 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}