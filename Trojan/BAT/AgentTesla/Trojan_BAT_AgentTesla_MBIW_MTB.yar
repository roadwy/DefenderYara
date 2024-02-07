
rule Trojan_BAT_AgentTesla_MBIW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 08 00 00 14 00 "
		
	strings :
		$a_01_0 = {0f 53 00 74 00 72 00 69 00 6e 00 67 00 31 } //0a 00 
		$a_01_1 = {4c 00 6f 00 2d 00 61 00 64 00 20 00 00 03 2d 00 00 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //0a 00 
		$a_01_2 = {4c 00 6f 00 61 00 64 00 00 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //01 00 
		$a_01_3 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_5 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_6 = {53 70 6c 69 74 } //01 00  Split
		$a_01_7 = {54 6f 49 6e 74 33 32 } //00 00  ToInt32
	condition:
		any of ($a_*)
 
}