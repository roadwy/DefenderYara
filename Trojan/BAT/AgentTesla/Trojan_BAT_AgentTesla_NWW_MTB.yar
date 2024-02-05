
rule Trojan_BAT_AgentTesla_NWW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 0f 10 00 00 95 5f 7e 07 00 00 04 17 9a 20 8a 0c 00 00 95 61 61 80 05 00 00 04 38 64 11 00 00 7e 05 00 00 04 7e 07 00 00 04 17 9a 20 cf 09 00 00 } //01 00 
		$a_01_1 = {20 1a 0f 00 00 95 e0 95 7e 24 00 00 04 20 73 0e 00 00 95 61 7e 24 00 00 04 20 22 12 00 00 95 2e 03 17 2b 01 16 58 } //00 00 
	condition:
		any of ($a_*)
 
}