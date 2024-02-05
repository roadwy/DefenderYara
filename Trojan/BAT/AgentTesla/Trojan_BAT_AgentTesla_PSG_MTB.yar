
rule Trojan_BAT_AgentTesla_PSG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 14 11 16 18 6f 90 01 03 0a 20 03 02 00 00 28 90 01 03 0a 13 18 11 15 11 18 6f 90 01 03 0a 00 11 16 18 58 13 16 00 11 16 11 14 6f 90 01 03 0a fe 04 13 19 11 19 2d c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}