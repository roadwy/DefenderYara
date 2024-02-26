
rule Trojan_BAT_AgentTesla_SV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 09 5d 13 04 06 1f 16 5d 13 09 06 17 58 09 5d 13 0a 07 11 04 91 11 05 11 09 91 61 13 0b 11 0b 07 11 0a 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0c 07 11 04 11 0c d2 9c 06 17 58 0a 06 09 11 06 17 58 5a fe 04 13 0d 11 0d 2d b3 } //00 00 
	condition:
		any of ($a_*)
 
}