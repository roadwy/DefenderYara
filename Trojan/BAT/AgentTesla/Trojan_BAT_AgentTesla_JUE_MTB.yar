
rule Trojan_BAT_AgentTesla_JUE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JUE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 09 00 00 "
		
	strings :
		$a_81_0 = {12 04 30 04 48 04 20 00 31 04 30 04 3b 04 30 04 3d 04 41 04 20 00 34 04 3e 04 20 00 3e 04 31 04 } //20 Ваш баланс до об
		$a_01_1 = {65 00 6c 00 6c 00 00 2d 53 00 74 00 61 00 72 00 74 00 2d 00 53 00 6c 00 65 00 65 00 70 00 20 00 } //20 ellⴀStart-Sleep 
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 73 74 6f 72 65 32 2e 67 6f 66 69 6c 65 2e 69 6f 2f 64 6f 77 6e 6c 6f 61 64 2f } //1 https://store2.gofile.io/download/
		$a_81_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_7 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_81_0  & 1)*20+(#a_01_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=26
 
}