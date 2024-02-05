
rule Trojan_BAT_AgentTesla_MBIL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 a1 03 00 70 72 a7 03 00 70 6f 90 01 01 00 00 0a 72 ab 03 00 70 72 b1 03 00 70 90 00 } //01 00 
		$a_01_1 = {20 00 4c 00 6f 00 2d 00 61 00 64 00 20 00 00 03 2d 00 00 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //00 00 
	condition:
		any of ($a_*)
 
}