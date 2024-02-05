
rule Trojan_BAT_AgentTesla_MBGW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 04 11 05 6f 90 01 01 00 00 0a 13 08 07 11 04 11 05 6f 90 01 01 00 00 0a 13 09 11 09 28 90 01 01 00 00 0a 13 0a 09 08 11 0a d2 9c 11 05 17 58 13 05 11 05 07 6f 90 01 01 00 00 0a 32 c9 90 00 } //01 00 
		$a_01_1 = {0b 16 0c 20 00 ba 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}