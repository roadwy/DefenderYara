
rule Trojan_BAT_AgentTesla_EAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 02 2a 00 28 90 01 01 00 00 06 13 00 38 90 01 01 00 00 00 02 11 01 28 90 01 01 00 00 06 13 02 38 90 01 01 00 00 00 28 90 01 01 00 00 0a 11 00 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 01 38 90 00 } //3
		$a_01_1 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}