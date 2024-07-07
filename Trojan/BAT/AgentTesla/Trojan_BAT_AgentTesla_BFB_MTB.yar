
rule Trojan_BAT_AgentTesla_BFB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 04 07 90 01 05 28 90 01 04 6a 61 b7 28 90 01 03 0a 90 02 04 28 90 01 03 0a 13 05 08 11 05 90 01 05 26 07 04 90 01 05 17 da 90 00 } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //1 ISectionEntry
		$a_81_4 = {58 4f 52 5f 44 65 63 72 79 70 74 } //1 XOR_Decrypt
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}
rule Trojan_BAT_AgentTesla_BFB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 0a 00 00 "
		
	strings :
		$a_81_0 = {47 61 72 72 69 78 2e 45 78 70 6c 6f 72 65 72 31 } //10 Garrix.Explorer1
		$a_81_1 = {53 55 50 45 52 4d 45 } //10 SUPERME
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 74 68 6f 64 } //1 InvokeMethod
		$a_81_6 = {41 70 70 65 6e 64 } //1 Append
		$a_81_7 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_81_8 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_9 = {53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 } //1 System.Convert
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=27
 
}