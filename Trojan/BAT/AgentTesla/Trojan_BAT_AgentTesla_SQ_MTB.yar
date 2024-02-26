
rule Trojan_BAT_AgentTesla_SQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {03 50 09 03 50 8e 69 6a 5d b7 03 50 09 03 50 8e 69 6a 5d b7 91 07 09 07 8e 69 6a 5d b7 91 61 03 50 09 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 90 01 04 d6 20 90 01 04 5d b4 9c 09 17 6a d6 0d 09 08 31 bb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_SQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 08 5d 13 04 06 17 58 08 5d 13 0a 07 11 0a 91 20 00 01 00 00 58 13 0b 07 11 04 91 13 0c 11 0c 11 06 06 1f 16 5d 91 61 13 0d 11 0d 11 0b 59 13 0e 07 11 04 11 0e 20 00 01 00 00 5d d2 9c 06 17 58 0a 06 08 11 07 17 58 5a fe 04 13 0f 11 0f 2d af } //00 00 
	condition:
		any of ($a_*)
 
}