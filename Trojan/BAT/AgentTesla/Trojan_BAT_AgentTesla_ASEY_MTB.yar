
rule Trojan_BAT_AgentTesla_ASEY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 11 08 09 06 09 91 7e 90 01 01 01 00 04 59 d2 9c 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}