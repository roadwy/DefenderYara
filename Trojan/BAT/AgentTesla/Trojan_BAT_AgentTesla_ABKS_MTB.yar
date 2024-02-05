
rule Trojan_BAT_AgentTesla_ABKS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {17 59 7e 11 00 00 04 20 73 01 00 00 95 5f 7e 11 00 00 04 20 d6 01 00 00 95 61 58 80 20 00 00 04 7e 20 00 00 04 7e 11 00 00 04 20 fe 02 00 00 95 33 72 7e 23 00 00 04 1f 1e 11 24 11 22 1b 95 59 7e 11 00 00 04 20 e7 01 00 00 95 59 7e 11 00 00 04 20 00 01 00 00 95 1f 1f 5f 64 } //00 00 
	condition:
		any of ($a_*)
 
}