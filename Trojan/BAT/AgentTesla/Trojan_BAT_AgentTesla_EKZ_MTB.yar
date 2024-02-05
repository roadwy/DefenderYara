
rule Trojan_BAT_AgentTesla_EKZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 09 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 28 90 01 03 0a 13 04 07 09 02 09 91 11 04 b4 61 9c 09 17 d6 0d 90 00 } //01 00 
		$a_01_1 = {00 54 6f 49 6e 74 33 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}