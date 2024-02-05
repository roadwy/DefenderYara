
rule Trojan_BAT_AgentTesla_PSGM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 28 02 00 00 0a 0a 28 90 01 03 0a 0b 07 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 07 6f 90 01 03 0a 1e 5b 8d 08 00 00 01 0c 06 8e 69 08 8e 69 59 8d 08 00 00 01 0d 06 08 08 8e 69 28 90 01 03 0a 06 08 8e 69 09 16 09 8e 69 28 90 01 03 0a 07 08 6f 90 01 03 0a 07 17 6f 90 01 03 0a 07 07 6f 90 01 03 0a 07 6f 90 01 03 0a 6f 90 01 03 0a 13 04 09 73 90 01 03 0a 13 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}