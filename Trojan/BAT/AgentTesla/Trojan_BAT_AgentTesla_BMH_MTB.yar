
rule Trojan_BAT_AgentTesla_BMH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {67 65 74 5f 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //1 get_OffsetMarshaler
		$a_81_1 = {67 65 74 5f 52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //1 get_ReturnMessage
		$a_81_2 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_6 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_81_7 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_8 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_9 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_81_10 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_11 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_12 = {47 65 74 41 73 73 65 6d 62 6c 69 65 73 } //1 GetAssemblies
		$a_81_13 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}