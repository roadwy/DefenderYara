
rule Trojan_BAT_AgentTesla_BQG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_02_0 = {08 16 20 00 10 00 00 6f 90 01 03 0a 13 04 11 04 16 fe 02 13 05 11 05 2c 0c 09 08 16 11 04 6f 90 01 03 0a 00 00 00 00 11 04 16 fe 02 13 06 11 06 2d 90 00 } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_4 = {52 65 73 74 72 69 63 74 65 64 45 72 72 6f 72 } //1 RestrictedError
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}