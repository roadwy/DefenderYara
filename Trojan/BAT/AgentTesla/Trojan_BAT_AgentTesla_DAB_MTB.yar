
rule Trojan_BAT_AgentTesla_DAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 05 11 0a 75 90 01 01 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 90 01 01 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 90 01 01 00 00 0a 26 1f 11 13 0e 38 90 01 01 fe ff ff 11 09 17 58 13 09 1e 13 0e 38 90 01 01 fe ff ff 11 09 11 07 31 08 1b 13 0e 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}