
rule Trojan_BAT_AgentTesla_IO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 9f a2 3f 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 b1 00 00 00 29 00 00 00 41 01 00 00 } //10
		$a_01_1 = {57 97 a2 3f 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 b7 00 00 00 35 00 00 00 71 01 00 00 } //10
		$a_01_2 = {24 62 39 62 30 36 36 35 32 2d 61 61 37 39 2d 34 65 33 39 2d 61 35 33 63 2d 30 36 37 39 34 62 31 30 30 66 37 34 } //1 $b9b06652-aa79-4e39-a53c-06794b100f74
		$a_01_3 = {54 72 61 66 66 69 63 53 69 6d 75 6c 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 TrafficSimulation.Properties.Resources
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_IO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.IO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {64 30 64 32 63 66 62 62 2d 63 30 36 63 2d 34 64 62 65 2d 61 66 38 61 2d 61 65 30 66 62 62 36 61 32 64 62 30 } //1 d0d2cfbb-c06c-4dbe-af8a-ae0fbb6a2db0
		$a_81_1 = {4b 55 49 20 53 6f 6c 65 } //1 KUI Sole
		$a_81_2 = {53 70 6c 69 74 } //1 Split
		$a_81_3 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_6 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_7 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_81_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_10 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_12 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}