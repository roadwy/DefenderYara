
rule Trojan_BAT_AgentTesla_EQM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 90 01 05 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 90 01 05 03 08 18 58 17 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1b 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 90 00 } //01 00 
		$a_03_1 = {03 08 03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 90 01 05 03 08 18 58 17 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1b 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}