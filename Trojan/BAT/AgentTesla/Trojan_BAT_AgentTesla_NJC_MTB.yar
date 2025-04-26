
rule Trojan_BAT_AgentTesla_NJC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 08 05 00 00 07 0d 95 60 7e 2f 00 00 04 19 9a 20 76 04 00 00 95 61 11 06 0d 7e 2f 00 00 04 19 9a 20 80 02 00 00 95 2e 03 16 2b 01 17 17 59 7e 2f 00 00 04 19 9a 20 9e 04 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}