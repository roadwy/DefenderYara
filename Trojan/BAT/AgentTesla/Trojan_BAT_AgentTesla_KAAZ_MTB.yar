
rule Trojan_BAT_AgentTesla_KAAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 11 05 08 8e 69 5d 13 09 11 05 09 6f 90 01 01 00 00 0a 5d 13 0a 08 11 09 91 13 0b 09 11 0a 6f 90 01 01 00 00 0a 13 0c 02 08 11 05 28 90 01 01 00 00 06 13 0d 02 11 0b 11 0c 11 0d 28 90 01 01 00 00 06 13 0e 08 11 09 02 11 0e 28 90 01 01 00 00 06 9c 11 05 17 59 13 05 00 11 05 16 fe 04 16 fe 01 13 0f 11 0f 2d a2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}