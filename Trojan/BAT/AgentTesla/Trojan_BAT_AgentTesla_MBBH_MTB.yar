
rule Trojan_BAT_AgentTesla_MBBH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 6d 03 00 00 95 5f 7e 45 00 00 04 20 87 09 00 00 95 61 58 13 39 38 a8 04 00 00 11 39 7e 45 00 00 04 20 6f 10 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBBH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 11 90 01 01 11 90 01 01 11 90 01 01 8e 69 5d 91 11 90 01 01 11 90 01 01 1f 90 01 01 5d 91 61 7e 90 01 03 04 28 90 01 03 06 11 90 01 01 11 90 01 01 17 58 11 90 01 01 8e 69 5d 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBBH_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 2f 00 00 0a 00 06 72 f8 02 00 70 6f 90 01 01 00 00 0a 74 90 01 01 00 00 01 72 fe 02 00 70 72 02 03 00 70 6f 90 01 01 00 00 0a 17 8d 90 01 01 00 00 01 25 16 1f 2d 9d 6f 90 01 01 00 00 0a 0b 07 8e 69 8d 90 01 01 00 00 01 0c 16 13 05 2b 18 00 08 11 05 07 11 05 9a 1f 10 28 90 01 01 00 00 0a d2 9c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}