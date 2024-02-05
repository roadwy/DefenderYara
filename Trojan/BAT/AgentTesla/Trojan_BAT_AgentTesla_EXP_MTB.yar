
rule Trojan_BAT_AgentTesla_EXP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 04 17 58 20 00 3a 00 00 5d 91 59 11 03 58 11 03 5d 13 01 20 00 00 00 00 } //01 00 
		$a_03_1 = {11 01 11 00 03 1f 16 5d 90 01 05 61 13 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}