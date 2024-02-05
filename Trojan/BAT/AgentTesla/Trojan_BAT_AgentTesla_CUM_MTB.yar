
rule Trojan_BAT_AgentTesla_CUM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 06 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 07 06 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 07 6f 90 01 03 0a 02 16 02 8e 69 6f 90 01 03 0a 0c 08 8e 69 1f 10 59 8d 90 01 03 01 0d 08 1f 10 09 16 08 8e 69 1f 10 59 28 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 73 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}