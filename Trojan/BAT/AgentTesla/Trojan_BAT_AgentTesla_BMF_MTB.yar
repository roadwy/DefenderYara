
rule Trojan_BAT_AgentTesla_BMF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_2 = {46 69 6c 6c 52 65 63 74 61 } //1 FillRecta
		$a_81_3 = {41 73 73 6f 63 69 61 74 65 73 } //1 Associates
		$a_81_4 = {43 6f 6c 6f 72 43 6f 6e 76 65 72 74 65 72 } //1 ColorConverter
		$a_81_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_6 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_9 = {4c 79 64 69 6f } //1 Lydio
		$a_81_10 = {6f 72 70 68 69 } //1 orphi
		$a_81_11 = {47 65 74 44 6f 6d 61 69 6e 00 4c 6f 61 64 } //1 敇䑴浯楡n潌摡
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}