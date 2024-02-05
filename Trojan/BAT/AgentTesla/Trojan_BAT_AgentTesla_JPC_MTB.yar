
rule Trojan_BAT_AgentTesla_JPC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a dd 90 01 03 00 08 39 90 01 03 00 08 6f 90 00 } //01 00 
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00 
		$a_81_2 = {47 65 74 54 79 70 65 73 } //01 00 
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}