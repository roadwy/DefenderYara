
rule Trojan_BAT_AgentTesla_ABFN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1a 9a 11 0b 13 07 1b 95 7e e4 00 00 04 20 c7 02 00 00 95 5a 7e e4 00 00 04 20 2a 04 00 00 95 2e 05 16 06 0a 2b 01 17 17 59 7e e4 00 00 04 20 97 03 00 00 95 11 0b 13 0b 5f 7e e4 00 00 04 20 15 03 00 00 95 61 61 81 07 00 00 01 38 51 03 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}