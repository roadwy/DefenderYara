
rule Trojan_BAT_AgentTesla_ID_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {24 31 65 66 64 64 32 65 31 2d 34 61 38 31 2d 34 31 66 30 2d 61 30 61 31 2d 66 37 37 61 64 35 31 63 65 32 36 66 } //1 $1efdd2e1-4a81-41f0-a0a1-f77ad51ce26f
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
		$a_81_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_6 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_7 = {42 69 6e 64 69 6e 67 46 6c 61 67 73 } //1 BindingFlags
		$a_81_8 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_9 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_10 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_81_11 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_ID_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0a 00 00 "
		
	strings :
		$a_81_0 = {24 35 37 35 30 35 32 31 66 2d 37 66 33 37 2d 34 65 36 61 2d 38 38 61 32 2d 63 35 31 35 32 32 39 39 32 37 30 35 } //20 $5750521f-7f37-4e6a-88a2-c51522992705
		$a_81_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_2 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_3 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=24
 
}
rule Trojan_BAT_AgentTesla_ID_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ID!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 05 00 00 06 72 63 04 00 70 72 67 04 00 70 6f 7c 00 00 0a 17 8d 57 00 00 01 25 16 1f 2d 9d 6f 7d 00 00 0a 0b 07 8e 69 8d 58 00 00 01 0c 16 13 07 2b 15 } //1
		$a_01_1 = {08 11 07 07 11 07 9a 1f 10 28 7e 00 00 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}