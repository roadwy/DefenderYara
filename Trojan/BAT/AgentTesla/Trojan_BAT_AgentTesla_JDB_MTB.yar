
rule Trojan_BAT_AgentTesla_JDB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {2b 28 08 07 6f 90 01 03 0a 13 05 06 11 05 28 90 01 03 0a 11 04 da 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a 07 17 d6 0b 07 08 6f 90 01 03 0a fe 04 13 06 11 06 2d c9 90 00 } //10
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}