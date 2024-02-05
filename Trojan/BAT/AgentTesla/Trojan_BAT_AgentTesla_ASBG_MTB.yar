
rule Trojan_BAT_AgentTesla_ASBG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 0b 2b 23 00 09 11 0b 18 6f 90 01 01 00 00 0a 13 0c 11 04 11 0b 18 5b 11 0c 1f 10 28 90 01 01 00 00 0a 9c 00 11 0b 18 58 13 0b 11 0b 09 6f 90 01 01 00 00 0a fe 04 13 0d 11 0d 2d cd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}