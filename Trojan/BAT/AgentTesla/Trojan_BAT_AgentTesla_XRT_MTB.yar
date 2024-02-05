
rule Trojan_BAT_AgentTesla_XRT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.XRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {00 16 13 05 2b 27 00 09 11 04 11 05 28 90 01 03 06 13 06 11 06 28 90 01 03 0a 13 07 08 11 07 d2 6f 90 01 03 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 08 11 08 2d ce 07 17 58 0b 00 11 04 17 58 13 04 11 04 20 00 7a 00 00 fe 04 13 09 11 09 2d ae 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}