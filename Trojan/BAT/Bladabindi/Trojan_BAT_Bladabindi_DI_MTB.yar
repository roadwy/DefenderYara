
rule Trojan_BAT_Bladabindi_DI_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 09 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 1e d8 1e 6f ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 9c 11 04 17 d6 13 04 11 04 09 31 e0 } //20
		$a_03_1 = {08 09 07 09 9a 1f 10 28 ?? ?? ?? 0a 9c 09 17 58 0d 09 07 8e 69 3f e6 ff ff ff } //20
		$a_81_2 = {43 6f 6e 76 65 72 74 } //5 Convert
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {53 70 6c 69 74 } //1 Split
		$a_81_5 = {54 6f 42 79 74 65 } //1 ToByte
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_8 = {42 69 6e 61 72 79 54 6f 53 74 72 69 6e 67 } //1 BinaryToString
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*20+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=28
 
}