
rule Trojan_BAT_AgentTesla_NWY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 21 0a 00 00 95 e0 95 7e 1f 00 00 04 17 9a 20 99 0d 00 00 95 61 7e 1f 00 00 04 17 9a 20 e4 07 00 00 95 2e 03 17 2b 01 16 58 7e 02 00 00 04 7e 1f 00 00 04 17 9a 20 26 05 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}