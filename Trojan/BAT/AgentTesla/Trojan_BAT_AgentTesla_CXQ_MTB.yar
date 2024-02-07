
rule Trojan_BAT_AgentTesla_CXQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 06 03 6f 90 01 03 0a 5d 17 58 28 90 01 03 0a 28 90 01 03 0a 59 0c 07 08 28 90 01 03 0a 13 05 12 05 28 90 01 03 0a 28 90 01 03 0a 0b 06 17 58 0a 06 02 6f 90 01 03 0a fe 02 16 90 09 0c 00 02 06 28 90 01 03 0a 28 90 01 03 0a 90 00 } //0a 00 
		$a_03_1 = {03 07 03 6f 90 01 03 0a 5d 17 58 28 90 01 03 0a 28 90 01 03 0a 59 0c 06 08 28 90 01 03 0a 0d 12 03 28 90 01 03 0a 28 90 01 03 0a 0a 07 17 58 0b 07 02 6f 90 01 03 0a 90 09 0c 00 02 07 28 90 01 03 0a 28 90 01 03 0a 90 00 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}