
rule Trojan_BAT_AgentTesla_AABD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 13 0a 2b 6f 08 11 0a 11 09 6f 90 01 01 00 00 0a 13 0b 16 13 0c 11 05 11 08 9a 13 0d 11 0d 72 1e 11 00 70 28 90 01 01 00 00 0a 2d 1e 11 0d 72 22 11 00 70 28 90 01 01 00 00 0a 2d 1b 11 0d 72 26 11 00 70 28 90 01 01 00 00 0a 2d 18 2b 1f 12 0b 28 90 01 01 00 00 0a 13 0c 2b 14 12 0b 28 90 01 01 00 00 0a 13 0c 2b 09 12 0b 28 90 01 01 00 00 0a 13 0c 07 11 0c 6f 90 01 01 00 00 0a 11 0a 17 58 13 0a 11 0a 09 32 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}