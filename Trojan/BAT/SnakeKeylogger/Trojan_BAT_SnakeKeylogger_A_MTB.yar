
rule Trojan_BAT_SnakeKeylogger_A_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 50 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 } //2 PP000000000000001
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 31 } //2 WindowsApp1
		$a_01_2 = {4b 30 30 30 30 30 31 } //2 K000001
		$a_01_3 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 } //1 GetMethod
		$a_01_4 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}
rule Trojan_BAT_SnakeKeylogger_A_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {57 95 a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 9e 00 00 00 2b 00 00 00 05 01 00 00 45 01 00 00 64 01 00 00 } //1
		$a_81_1 = {39 63 36 32 35 31 64 63 2d 36 61 39 33 2d 34 38 62 62 2d 62 63 63 66 2d 65 31 38 37 34 32 30 30 35 38 63 61 } //1 9c6251dc-6a93-48bb-bccf-e187420058ca
		$a_81_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_81_7 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}