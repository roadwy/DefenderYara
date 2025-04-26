
rule Trojan_BAT_AgentTesla_LJB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {4c 32 33 64 33 32 64 4c 78 64 6d 23 64 65 64 6d 32 33 } //1 L23d32dLxdm#dedm23
		$a_81_1 = {4c 4b 73 6e 7a 45 4c 4b 73 6e 7a 6e 4c 4b 73 6e 7a 74 72 79 50 4c 4b 73 6e 7a 6f 69 4c 4b 73 6e 7a 6e 4c 4b 73 6e 7a 74 } //1 LKsnzELKsnznLKsnztryPLKsnzoiLKsnznLKsnzt
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {47 65 74 50 72 6f 70 65 72 74 79 } //1 GetProperty
		$a_01_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_LJB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.LJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 6f ?? ?? ?? 0a 00 08 18 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 2b 00 11 04 2a } //10
		$a_01_1 = {24 30 32 62 36 39 63 64 32 2d 65 66 39 36 2d 34 64 35 32 2d 62 34 64 39 2d 32 31 34 61 32 32 32 38 38 64 31 62 } //10 $02b69cd2-ef96-4d52-b4d9-214a22288d1b
		$a_01_2 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_01_7 = {44 75 61 6c 53 6e 61 6b 65 } //1 DualSnake
		$a_01_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=17
 
}