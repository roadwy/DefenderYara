
rule Trojan_BAT_AgentTesla_NWP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 42 06 00 00 95 61 7e 1d 00 00 04 19 9a 20 3e 0c 00 00 95 2e 03 17 2b 01 16 58 06 13 05 7e 1d 00 00 04 16 9a 7e 1d 00 00 04 19 9a 20 b6 0d 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}