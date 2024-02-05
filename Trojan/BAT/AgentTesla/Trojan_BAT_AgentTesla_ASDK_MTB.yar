
rule Trojan_BAT_AgentTesla_ASDK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 91 13 09 11 07 11 08 61 11 09 20 00 01 00 00 58 20 00 01 00 00 5d 59 } //01 00 
		$a_01_1 = {51 75 61 6e 4c 79 51 75 61 6e 43 61 66 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}