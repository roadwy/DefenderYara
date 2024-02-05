
rule Trojan_BAT_AgentTesla_KRIMI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KRIMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 08 07 8e 69 5d 07 08 07 8e 69 5d 91 02 7b e7 00 00 04 6f 90 01 03 0a 08 02 7b e7 00 00 04 6f 90 01 03 0a 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 28 90 01 03 0a 07 08 17 58 07 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d 99 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}