
rule Trojan_BAT_Zema_SBP_MTB{
	meta:
		description = "Trojan:BAT/Zema.SBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {73 64 66 73 64 66 73 64 } //1 sdfsdfsd
		$a_81_1 = {66 61 73 61 73 64 61 73 64 61 73 2e 65 78 65 } //1 fasasdasdas.exe
		$a_81_2 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_3 = {6d 5f 49 73 52 65 70 47 32 44 65 63 6f 64 65 72 73 } //1 m_IsRepG2Decoders
		$a_81_4 = {53 65 74 44 69 63 74 69 6f 6e 61 72 79 53 69 7a 65 } //1 SetDictionarySize
		$a_81_5 = {44 65 63 6f 64 65 57 69 74 68 4d 61 74 63 68 42 79 74 65 } //1 DecodeWithMatchByte
		$a_81_6 = {55 70 64 61 74 65 53 68 6f 72 74 52 65 70 } //1 UpdateShortRep
		$a_81_7 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_8 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}