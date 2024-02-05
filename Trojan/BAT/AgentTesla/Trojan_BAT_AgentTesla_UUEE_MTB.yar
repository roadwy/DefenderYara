
rule Trojan_BAT_AgentTesla_UUEE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.UUEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 72 01 00 00 70 6f 90 01 03 0a 0b 00 07 14 fe 01 16 fe 01 0d 09 2d 02 de 56 07 6f 90 01 03 0a d4 8d 13 00 00 01 0c 07 08 16 08 8e 69 6f 90 01 03 0a 26 08 28 90 01 03 0a 72 13 00 00 70 6f 90 01 03 0a 28 90 01 03 06 0c 08 28 90 01 03 0a 6f 90 01 03 0a 14 14 6f 90 01 03 0a 26 00 de 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}