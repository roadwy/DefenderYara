
rule Trojan_BAT_AgentTesla_GZD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 0c 20 1f 8f fb 0e 0b 00 38 9a 00 00 00 07 20 f1 8e fb 0e fe 01 0d 09 2c 0c 20 18 8f fb 0e 0b 00 38 82 00 00 00 00 20 07 8f fb 0e 0b 17 13 04 } //1
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 } //1 System.Convert
		$a_01_2 = {46 00 72 00 60 00 6f 00 } //1 Fr`o
		$a_01_3 = {6d 00 60 00 42 00 61 00 73 00 } //1 m`Bas
		$a_01_4 = {65 00 36 00 34 00 60 00 53 00 74 00 } //1 e64`St
		$a_01_5 = {72 00 69 00 60 00 6e 00 67 00 } //1 ri`ng
		$a_01_6 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_7 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_8 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}