
rule Trojan_BAT_AgentTesla_PSAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 28 0f 00 00 0a 6f 10 90 01 03 6f 11 90 01 03 0a 06 73 12 90 01 03 0b 2b 09 2b 0a 2b 0f 17 2c f7 de 30 07 2b f4 6f 13 90 01 03 2b ef 0c 2b ee 90 00 } //5
		$a_03_1 = {11 04 12 05 28 1f 90 01 03 07 09 18 6f 20 90 01 03 06 28 21 90 01 03 13 06 08 09 11 06 6f 22 90 01 03 de 0c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}