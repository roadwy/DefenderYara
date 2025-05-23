
rule Trojan_BAT_AgentTesla_BET_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0b 00 00 "
		
	strings :
		$a_81_0 = {34 63 37 38 65 39 64 37 2d 38 66 61 63 2d 34 37 33 35 2d 39 63 39 62 2d 62 38 31 33 61 62 66 62 63 30 35 39 } //10 4c78e9d7-8fac-4735-9c9b-b813abfbc059
		$a_81_1 = {65 35 64 36 35 37 61 32 2d 37 32 39 34 2d 34 65 65 32 2d 61 65 64 35 2d 63 38 33 30 34 30 34 62 36 38 36 33 } //10 e5d657a2-7294-4ee2-aed5-c830404b6863
		$a_81_2 = {65 33 35 66 62 61 35 30 2d 64 33 65 62 2d 34 33 38 66 2d 62 34 37 65 2d 31 30 66 34 66 34 31 61 36 33 34 32 } //10 e35fba50-d3eb-438f-b47e-10f4f41a6342
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_6 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_81_7 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //1 ISectionEntry
		$a_81_8 = {58 4f 52 5f 44 65 63 72 79 70 74 } //1 XOR_Decrypt
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=18
 
}