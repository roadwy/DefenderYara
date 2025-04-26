
rule Trojan_BAT_AgentTesla_NJT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 73 0e 00 00 95 5f 7e 0e 00 00 04 20 4f 0a 00 00 95 61 61 81 07 00 00 01 7e 14 00 00 04 19 9a 1f 4f 95 7e 0e 00 00 04 20 51 04 00 00 } //1
		$a_01_1 = {7e 0c 00 00 04 18 9a 7e 2b 00 00 04 20 e7 11 00 00 95 e0 95 7e 2b 00 00 04 20 77 08 00 00 95 61 7e 2b 00 00 04 20 8e 10 00 00 95 2e 07 11 04 13 05 17 2b 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}