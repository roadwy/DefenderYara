
rule Trojan_BAT_AgentTesla_OW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 90 02 05 28 90 02 04 28 90 02 04 04 07 6f 90 02 04 28 90 02 04 6a 61 b7 28 90 02 04 13 07 90 00 } //1
		$a_81_1 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //1 ISectionEntry
		$a_81_2 = {67 65 74 5f 43 68 61 72 73 } //1 get_Chars
		$a_81_3 = {54 6f 4c 6f 6e 67 } //1 ToLong
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}