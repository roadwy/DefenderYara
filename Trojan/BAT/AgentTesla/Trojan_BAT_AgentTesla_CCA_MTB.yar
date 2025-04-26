
rule Trojan_BAT_AgentTesla_CCA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_02_0 = {06 11 04 1f 10 28 ?? ?? ?? 0a d1 6f ?? ?? ?? 0a 26 } //1
		$a_81_1 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_2 = {54 6f 55 49 6e 74 33 32 } //1 ToUInt32
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_5 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_6 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_7 = {4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //1 OffsetMarshaler
		$a_81_8 = {52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //1 ReturnMessage
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}