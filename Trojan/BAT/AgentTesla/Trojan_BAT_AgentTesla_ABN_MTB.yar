
rule Trojan_BAT_AgentTesla_ABN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {1b 9a 20 31 11 00 00 95 36 03 16 2b 01 17 17 59 7e 2f 00 00 04 1b 9a 20 76 10 00 00 95 5f 09 0a 7e 2f 00 00 04 1b 9a 20 d2 10 00 00 95 61 58 81 0a 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}