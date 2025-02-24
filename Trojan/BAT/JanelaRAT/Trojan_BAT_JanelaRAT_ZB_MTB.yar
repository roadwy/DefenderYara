
rule Trojan_BAT_JanelaRAT_ZB_MTB{
	meta:
		description = "Trojan:BAT/JanelaRAT.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {3c 4a 61 6e 65 6c 61 3e 6b } //1 <Janela>k
		$a_81_1 = {73 65 74 5f 4a 61 6e 65 6c 61 } //1 set_Janela
		$a_81_2 = {67 65 74 5f 53 79 73 74 65 6d 49 6e 66 6f 73 } //1 get_SystemInfos
		$a_81_3 = {68 6f 6f 6b 53 74 72 75 63 74 } //1 hookStruct
		$a_81_4 = {47 65 74 52 65 63 79 63 6c 65 64 } //1 GetRecycled
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_6 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_7 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //1 get_MachineName
		$a_81_8 = {57 72 69 74 65 41 6c 6c 54 65 78 74 } //1 WriteAllText
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}