
rule Trojan_BAT_AgentTesla_ASCS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 20 16 a8 02 00 0d 2b 36 00 07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 6f 90 01 01 01 00 0a 61 07 09 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 06 11 06 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}