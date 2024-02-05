
rule Trojan_BAT_AgentTesla_DAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {20 b4 09 00 00 95 2e 03 16 2b 01 17 17 59 7e 26 00 00 04 20 ac 03 00 00 95 5f 7e 26 00 00 04 11 28 13 28 20 43 0f 00 00 95 61 58 80 42 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}