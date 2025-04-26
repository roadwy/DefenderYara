
rule Trojan_BAT_AgentTesla_NJP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 2a 00 00 04 ?? 0a 16 9a 1f 44 95 7e 2a 00 00 04 17 9a 20 a0 0d 00 00 95 61 09 0a 7e 2a 00 00 04 17 9a 20 be 0a 00 00 95 2e 03 16 2b 01 17 7e 2a 00 00 04 17 9a 20 bb 02 00 00 20 } //1
		$a_01_1 = {7e 06 00 00 04 20 13 02 00 00 95 e0 95 7e 06 00 00 04 11 05 13 05 20 2b 08 00 00 95 61 7e 06 00 00 04 20 12 06 00 00 95 2e 05 08 0c 17 2b 08 16 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}