
rule Trojan_BAT_AgentTesla_ABX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 7b 0c 00 00 95 2e 03 17 2b 01 16 58 19 31 03 16 2b 01 17 7e 20 00 00 04 20 b2 0a 00 00 95 5a 7e 20 00 00 04 20 98 0e 00 00 95 58 61 81 07 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}