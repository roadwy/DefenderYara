
rule Trojan_BAT_AgentTesla_CTS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,35 00 35 00 0b 00 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //10 DebuggableAttribute
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 } //10 DebuggingMode
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 } //10 System.Convert
		$a_01_3 = {67 00 6e 00 69 00 72 00 74 00 53 00 34 00 36 00 65 00 73 00 61 00 42 00 6d 00 6f 00 72 00 46 00 } //10 gnirtS46esaBmorF
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //10 StrReverse
		$a_81_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {73 00 70 00 79 00 54 00 74 00 65 00 47 00 } //1 spyTteG
		$a_81_7 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_8 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_9 = {64 00 6f 00 68 00 74 00 65 00 4d 00 74 00 65 00 47 00 } //1 dohteMteG
		$a_01_10 = {65 00 6b 00 6f 00 76 00 6e 00 49 00 } //1 ekovnI
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_81_5  & 1)*1+(#a_01_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=53
 
}