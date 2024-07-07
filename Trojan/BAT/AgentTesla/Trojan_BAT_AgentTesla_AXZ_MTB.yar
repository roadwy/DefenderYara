
rule Trojan_BAT_AgentTesla_AXZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 09 20 1f 8f fb 0e 0b 00 2b 5f 07 20 f1 8e fb 0e fe 01 0d 09 2c 09 20 18 8f fb 0e 0b 00 2b 4a 00 20 07 8f fb 0e 0b 17 13 04 d0 6b 00 00 01 28 90 01 03 0a 72 11 cc 00 70 18 1b 8d 17 00 00 01 25 16 72 2b cc 00 70 a2 25 17 20 00 01 00 00 8c 65 00 00 01 a2 25 1a 17 8d 17 00 00 01 25 16 02 a2 a2 28 90 01 03 0a 0a 2b 00 06 2a 90 00 } //10
		$a_81_1 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_81_2 = {49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 35 } //1 I__________________5
		$a_81_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_81_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_5 = {54 6f 53 74 72 69 6e 67 } //1 ToString
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}