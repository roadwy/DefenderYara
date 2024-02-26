
rule Trojan_BAT_AgentTesla_MBEJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 8e 69 5d 02 06 07 06 8e 69 5d 91 09 07 09 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a d2 06 07 17 58 06 8e 69 5d 91 28 90 01 01 00 00 0a d2 59 20 00 01 00 00 58 28 90 01 01 00 00 06 28 90 01 01 00 00 0a d2 9c 07 15 58 0b 07 16 fe 04 16 fe 01 13 07 11 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}