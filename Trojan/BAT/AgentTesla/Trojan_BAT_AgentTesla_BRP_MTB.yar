
rule Trojan_BAT_AgentTesla_BRP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_00_0 = {8a a7 28 c8 da 08 05 86 7a 54 a0 63 f7 ba 8f 7d } //10
		$a_81_1 = {66 6c 6f 72 61 } //1 flora
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_3 = {53 6d 61 72 74 45 78 74 65 6e 73 69 6f 6e 73 } //1 SmartExtensions
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_7 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=16
 
}