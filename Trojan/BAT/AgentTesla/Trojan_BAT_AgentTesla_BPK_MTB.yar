
rule Trojan_BAT_AgentTesla_BPK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_81_0 = {5a 4a 34 46 41 37 45 5a 37 35 45 43 55 4a 42 5a } //10 ZJ4FA7EZ75ECUJBZ
		$a_81_1 = {66 6c 6f 72 61 } //1 flora
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_81_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_6 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_7 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_8 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=17
 
}