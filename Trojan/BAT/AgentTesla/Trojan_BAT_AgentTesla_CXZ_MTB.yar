
rule Trojan_BAT_AgentTesla_CXZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_03_0 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 09 20 1f 8f fb 0e 0b 00 2b 61 07 20 f1 8e fb 0e fe 01 0d 09 2c 09 20 18 8f fb 0e 0b 00 2b 4c 00 20 07 8f fb 0e 0b 17 13 04 d0 99 00 00 01 28 ?? ?? ?? 0a 14 72 2d bc 00 70 1b 8d 19 00 00 01 25 16 72 47 bc 00 70 a2 25 17 20 00 01 00 00 8c 82 00 00 01 a2 25 1a 17 8d 19 00 00 01 25 16 02 a2 a2 14 14 28 ?? ?? ?? 0a 0a 2b 00 06 2a } //10
		$a_81_1 = {46 6c 61 70 70 79 42 69 72 64 } //1 FlappyBird
		$a_81_2 = {49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 32 } //1 I______________________2
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_81_4 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_5 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_6 = {54 6f 53 74 72 69 6e 67 } //1 ToString
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=16
 
}