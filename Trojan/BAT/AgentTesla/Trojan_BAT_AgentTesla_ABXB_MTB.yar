
rule Trojan_BAT_AgentTesla_ABXB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 0d 16 13 04 2b 3c 00 16 13 04 2b 21 00 07 09 11 04 6f 90 01 01 00 00 0a 13 06 08 12 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 04 17 58 13 04 00 11 04 07 6f 90 01 01 00 00 0a fe 04 13 07 11 07 2d cf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}