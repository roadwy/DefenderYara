
rule Trojan_BAT_AgentTesla_AQT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {02 02 8e 69 17 da 91 1f 70 61 0c 02 8e 69 17 d6 17 da 17 d6 ?? ?? ?? ?? ?? 0d 02 8e 69 17 da 13 04 11 04 13 05 16 13 06 11 06 2c 42 09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=10
 
}
rule Trojan_BAT_AgentTesla_AQT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0c 00 00 "
		
	strings :
		$a_80_0 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 47 67 44 32 4c 43 2f } //transfer.sh/get/GgD2LC/  10
		$a_80_1 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 47 6b 56 4a 78 6a 2f } //transfer.sh/get/GkVJxj/  10
		$a_80_2 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 38 73 44 36 54 6f 2f } //transfer.sh/get/8sD6To/  10
		$a_80_3 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 71 78 76 77 37 45 2f } //transfer.sh/get/qxvw7E/  10
		$a_80_4 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 32 73 33 79 49 69 2f } //transfer.sh/get/2s3yIi/  10
		$a_81_5 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_81_6 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_81_7 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_9 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_10 = {4d 00 4f 00 4e 00 45 00 59 00 4d 00 4f 00 4e 00 45 00 59 00 4d 00 4f 00 4e 00 45 00 59 00 } //1 MONEYMONEYMONEY
		$a_01_11 = {47 00 48 00 4a 00 58 00 48 00 4a 00 48 00 53 00 48 00 53 00 44 00 4a 00 2e 00 42 00 4c 00 4f 00 4f 00 44 00 4d 00 4f 00 4e 00 45 00 59 00 } //1 GHJXHJHSHSDJ.BLOODMONEY
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*10+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=17
 
}