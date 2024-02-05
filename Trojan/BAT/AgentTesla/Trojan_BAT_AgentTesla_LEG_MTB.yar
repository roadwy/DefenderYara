
rule Trojan_BAT_AgentTesla_LEG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 02 08 93 06 08 06 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 28 90 01 03 0a 6f 90 01 03 0a 26 08 17 58 0c 08 02 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}