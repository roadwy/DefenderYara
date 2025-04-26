
rule Trojan_BAT_AgentTesla_EG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {11 06 11 06 11 00 94 11 06 11 02 94 58 20 00 01 00 00 5d 94 13 09 38 } //5
		$a_00_1 = {11 07 11 01 02 11 01 91 11 09 61 d2 9c } //5
		$a_00_2 = {9e 07 07 09 94 07 08 94 58 20 00 01 00 00 5d 94 13 08 11 06 06 02 06 91 11 08 61 d2 9c 06 17 58 0a 06 02 8e 69 } //10
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*10+(#a_81_3  & 1)*1) >=11
 
}
rule Trojan_BAT_AgentTesla_EG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {08 11 04 02 11 04 91 07 11 04 07 8e b7 5d 91 61 09 11 04 09 8e b7 5d 91 61 9c 11 04 17 d6 13 04 11 04 11 05 31 da } //10
		$a_81_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_2 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}