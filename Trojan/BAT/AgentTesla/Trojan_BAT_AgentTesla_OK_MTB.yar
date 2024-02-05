
rule Trojan_BAT_AgentTesla_OK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {16 13 04 07 09 11 90 01 01 6f 90 01 04 13 90 01 01 11 90 01 01 28 90 01 04 13 90 01 01 08 06 11 90 01 01 b4 9c 11 90 01 01 17 d6 13 90 01 01 11 90 01 01 16 31 90 01 01 06 17 d6 0a 09 17 d6 0d 09 20 90 01 04 31 90 01 01 02 72 90 01 04 1f 90 01 01 17 16 16 08 28 90 01 04 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}