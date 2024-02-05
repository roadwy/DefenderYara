
rule Trojan_BAT_AgentTesla_NWS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 73 01 00 00 95 5f 7e 1d 00 00 04 19 9a 20 ac 00 00 00 95 61 59 81 05 00 00 01 38 97 04 00 00 7e 1d 00 00 04 18 9a 1f 20 95 7e 1d 00 00 04 19 9a 07 0b 20 3b 03 00 00 95 40 84 00 00 00 7e 11 00 00 04 16 32 28 } //00 00 
	condition:
		any of ($a_*)
 
}