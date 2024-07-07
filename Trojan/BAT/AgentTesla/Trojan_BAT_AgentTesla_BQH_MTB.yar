
rule Trojan_BAT_AgentTesla_BQH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BQH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_02_0 = {70 18 1b 8d 90 01 03 01 25 16 72 90 01 03 70 a2 25 17 20 00 01 00 00 8c 90 01 03 01 a2 25 1a 17 8d 90 01 03 01 25 16 03 74 90 01 03 1b 28 90 01 03 06 a2 a2 28 90 01 03 0a 28 90 01 03 0a 0a 02 06 28 90 01 03 0a 72 90 01 03 70 18 17 8d 90 01 03 01 25 16 72 90 01 03 70 a2 28 90 00 } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_4 = {52 65 73 74 72 69 63 74 65 64 45 72 72 6f 72 } //1 RestrictedError
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=13
 
}