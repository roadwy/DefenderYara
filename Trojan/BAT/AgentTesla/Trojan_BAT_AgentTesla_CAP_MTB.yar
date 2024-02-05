
rule Trojan_BAT_AgentTesla_CAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 72 e3 05 00 70 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 0b 07 02 16 02 8e 69 6f 90 01 01 00 00 0a 0c 2b 00 08 2a 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}