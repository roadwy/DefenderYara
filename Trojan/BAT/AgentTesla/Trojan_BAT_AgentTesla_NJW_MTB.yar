
rule Trojan_BAT_AgentTesla_NJW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 d7 0b 00 00 95 e0 95 7e 2a 00 00 04 17 9a 20 9c 0e 00 00 95 61 7e 2a 00 00 04 17 9a 20 26 0e 00 00 95 2e 03 17 2b 07 16 } //01 00 
		$a_01_1 = {7e 1d 00 00 04 18 9a 20 c5 0f 00 00 95 e0 11 05 13 07 95 7e 1d 00 00 04 18 9a 20 32 0d 00 00 95 61 7e 1d 00 00 04 18 9a 20 0a 09 00 00 95 2e 03 } //00 00 
	condition:
		any of ($a_*)
 
}