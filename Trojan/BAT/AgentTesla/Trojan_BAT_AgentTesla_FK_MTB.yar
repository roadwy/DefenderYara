
rule Trojan_BAT_AgentTesla_FK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_03_0 = {16 0a 72 01 00 00 70 12 00 28 ?? ?? ?? 0a 2c 10 06 16 31 0c 06 20 e8 03 00 00 5a 28 ?? ?? ?? 0a de 03 } //10
		$a_03_1 = {70 12 01 28 ?? ?? ?? 0a 2c 10 07 16 31 0c 07 20 e8 03 00 00 5a 28 ?? ?? ?? 0a de 03 90 09 06 00 16 0b 72 } //10
		$a_03_2 = {26 de 00 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 73 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 01 00 00 1b 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 14 16 8d 01 00 00 01 6f ?? ?? ?? 0a 26 de 03 26 de 00 2a } //5
		$a_81_3 = {77 61 74 63 68 64 6f 67 } //1 watchdog
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {4c 6f 61 64 65 72 } //1 Loader
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=18
 
}
rule Trojan_BAT_AgentTesla_FK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0c 00 00 "
		
	strings :
		$a_81_0 = {24 32 62 32 30 34 30 37 65 2d 62 37 63 33 2d 34 66 39 65 2d 38 63 62 66 2d 33 64 39 62 30 64 36 62 35 62 66 32 } //20 $2b20407e-b7c3-4f9e-8cbf-3d9b0d6b5bf2
		$a_81_1 = {24 65 35 34 30 37 37 32 31 2d 31 31 32 63 2d 34 32 33 31 2d 62 33 39 36 2d 66 66 61 34 63 33 30 61 65 62 31 30 } //20 $e5407721-112c-4231-b396-ffa4c30aeb10
		$a_81_2 = {24 62 32 38 63 65 63 36 38 2d 66 37 37 35 2d 34 31 37 38 2d 62 61 33 33 2d 32 36 35 61 39 36 39 32 63 66 30 33 } //20 $b28cec68-f775-4178-ba33-265a9692cf03
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_9 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_10 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_11 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=23
 
}