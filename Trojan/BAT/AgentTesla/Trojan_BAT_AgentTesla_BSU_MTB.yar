
rule Trojan_BAT_AgentTesla_BSU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BSU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_81_0 = {31 62 62 30 39 66 33 35 2d 34 38 33 39 2d 34 63 31 37 2d 61 38 63 30 2d 37 65 32 38 37 63 39 65 36 63 39 64 } //10 1bb09f35-4839-4c17-a8c0-7e287c9e6c9d
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_5 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //1 DeflateStream
		$a_81_6 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_8 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=18
 
}