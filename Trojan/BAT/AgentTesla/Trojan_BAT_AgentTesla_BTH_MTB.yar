
rule Trojan_BAT_AgentTesla_BTH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {61 72 6f 6c 46 } //1 arolF
		$a_81_1 = {64 6f 68 74 65 4d 74 65 47 } //1 dohteMteG
		$a_81_2 = {53 6d 61 72 74 45 78 74 65 6e 73 69 6f 6e 73 } //1 SmartExtensions
		$a_81_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_81_7 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_8 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_9 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_10 = {4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //1 OffsetMarshaler
		$a_81_11 = {52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //1 ReturnMessage
		$a_81_12 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}