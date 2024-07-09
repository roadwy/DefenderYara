
rule Trojan_BAT_AgentTesla_IK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 9d a2 3d 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 60 00 00 00 19 00 00 00 4c 00 00 00 a1 01 00 00 37 } //10
		$a_01_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_4 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_5 = {43 6f 6e 66 75 73 65 72 45 78 } //1 ConfuserEx
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_BAT_AgentTesla_IK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.IK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 10 59 8d ?? ?? ?? ?? 13 04 09 1f 10 11 04 16 09 8e 69 1f 10 59 1f 10 58 1f 10 59 28 } //10
		$a_01_1 = {00 6f 00 45 00 69 00 62 00 72 00 36 00 34 00 31 00 56 00 4e 00 45 00 42 00 32 00 59 00 75 00 78 00 42 00 6b 00 38 00 4f 00 30 00 53 00 74 00 4d } //1
		$a_80_2 = {35 37 48 33 46 4e 50 43 35 34 4a 48 58 46 46 46 38 44 43 33 34 37 } //57H3FNPC54JHXFFF8DC347  1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_IK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.IK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_02_0 = {20 00 10 00 00 8d 0c 00 00 01 13 ?? 73 } //10
		$a_81_1 = {46 72 65 79 6a 61 20 74 68 65 20 46 72 65 79 6b 61 } //1 Freyja the Freyka
		$a_81_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_3 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_4 = {53 70 6c 69 74 } //1 Split
		$a_81_5 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_6 = {43 6f 6c 6c 65 63 74 } //1 Collect
		$a_81_7 = {00 33 32 30 31 32 32 32 33 35 39 35 39 5a 30 } //1
		$a_81_8 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_9 = {47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } //1 GetEnumerator
		$a_81_10 = {55 6e 61 72 79 4f 70 65 72 61 74 69 6f 6e } //1 UnaryOperation
		$a_81_11 = {41 64 64 52 61 6e 67 65 } //1 AddRange
		$a_81_12 = {4d 65 74 68 6f 64 49 6e 76 6f 6b 65 72 } //1 MethodInvoker
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}