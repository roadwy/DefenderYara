
rule Trojan_BAT_AgentTesla_BOQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BOQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {70 0c 07 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 0d 06 09 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 02 6f ?? ?? ?? 0a 16 02 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 20 ?? ?? ?? ?? 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f } //1
		$a_81_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_BOQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BOQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {53 6d 61 72 74 45 78 74 65 6e 73 69 6f 6e 73 } //10 SmartExtensions
		$a_81_1 = {5a 4a 34 46 41 37 45 5a 37 35 45 43 55 4a 42 5a } //10 ZJ4FA7EZ75ECUJBZ
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_81_6 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_7 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_8 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_9 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_10 = {66 6c 6f 72 61 } //1 flora
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=27
 
}