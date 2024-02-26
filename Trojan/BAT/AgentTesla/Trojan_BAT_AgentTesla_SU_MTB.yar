
rule Trojan_BAT_AgentTesla_SU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 11 05 11 04 5d 13 08 07 11 08 91 08 11 05 1f 16 5d 91 61 13 09 11 09 07 11 05 17 58 11 04 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0a 07 11 08 11 0a d2 9c 11 05 17 58 13 05 00 11 05 11 04 09 17 58 5a fe 04 13 0b 11 0b 2d b2 } //00 00 
	condition:
		any of ($a_*)
 
}