
rule Trojan_BAT_AgentTesla_CKS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a de 0a 08 2c 06 08 6f 90 01 03 0a dc 07 6f 90 01 03 0a 0d de 14 07 2c 06 07 6f 90 01 03 0a dc 90 00 } //01 00 
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //01 00 
		$a_01_2 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00 
		$a_01_3 = {41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //01 00 
		$a_01_4 = {00 43 6c 61 73 73 4c 69 62 72 61 72 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}