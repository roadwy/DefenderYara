
rule Trojan_BAT_AgentTesla_EHH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 07 06 07 91 20 90 01 04 59 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}