
rule Trojan_BAT_AgentTesla_WMP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.WMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 07 17 8d 90 01 03 01 25 16 1f 2d 9d 6f 90 01 03 0a 0c 73 90 01 03 0a 0d 16 13 08 2b 1b 09 11 08 08 11 08 9a 1f 10 28 90 01 03 0a d2 6f 90 01 03 0a 00 11 08 17 58 13 08 11 08 08 8e 69 fe 04 13 09 11 09 2d d8 90 0a 78 00 28 90 01 03 06 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}