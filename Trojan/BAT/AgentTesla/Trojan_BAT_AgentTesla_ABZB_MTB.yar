
rule Trojan_BAT_AgentTesla_ABZB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 2b 11 06 09 5d 13 07 11 06 09 5b 13 08 08 11 07 11 08 6f 90 01 01 00 00 0a 13 09 07 12 09 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 11 06 17 58 13 06 11 06 09 11 04 5a 32 cd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}