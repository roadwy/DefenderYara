
rule Trojan_BAT_AgentTesla_CQN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d 03 26 2b 03 0b 2b 00 06 16 73 90 01 03 0a 73 90 01 03 0a 90 01 01 2d 03 26 2b 03 0c 2b 00 08 07 6f 90 01 03 0a de 07 08 6f 90 01 03 0a dc 07 6f 90 01 03 0a 0d de 0e 07 6f 90 01 03 0a dc 90 00 } //01 00 
		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00 
		$a_01_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00 
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //00 00 
	condition:
		any of ($a_*)
 
}