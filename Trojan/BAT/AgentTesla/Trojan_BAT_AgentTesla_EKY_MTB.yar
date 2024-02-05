
rule Trojan_BAT_AgentTesla_EKY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 6d 00 6b 00 58 00 57 00 49 00 30 00 5a 00 41 00 41 00 41 00 13 01 44 00 13 01 59 00 4e 00 46 00 68 00 4d 00 45 00 4f 00 45 00 45 00 41 00 41 00 41 00 41 00 41 00 41 00 68 00 45 00 45 00 6b 00 } //01 00 
		$a_01_1 = {01 45 00 45 00 41 00 6f 00 35 00 70 00 46 00 31 00 6e 00 2b 00 41 00 68 00 62 00 2b 00 41 00 52 00 4d 00 48 00 45 00 51 00 63 00 36 00 71 00 76 } //00 00 
	condition:
		any of ($a_*)
 
}