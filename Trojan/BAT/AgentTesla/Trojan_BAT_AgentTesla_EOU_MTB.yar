
rule Trojan_BAT_AgentTesla_EOU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 01 11 03 20 00 60 00 00 5d 11 01 11 03 20 00 60 00 00 5d 91 11 02 11 03 1f 16 5d 90 01 05 61 11 01 11 03 17 58 20 00 60 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EOU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EOU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 7e 90 01 03 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 18 58 17 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1b 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 90 00 } //01 00 
		$a_01_1 = {73 00 73 00 73 00 73 00 73 00 72 00 72 00 72 00 72 00 72 00 72 00 72 00 72 00 72 00 73 00 64 00 61 00 73 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}