
rule Trojan_BAT_AgentTesla_JUR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {31 34 36 38 62 30 63 35 2d 39 64 61 63 2d 34 36 34 65 2d 61 33 64 30 2d 33 63 34 30 35 37 65 62 37 37 64 34 } //1 1468b0c5-9dac-464e-a3d0-3c4057eb77d4
		$a_81_1 = {00 58 58 44 45 00 } //1 堀䑘E
		$a_81_2 = {57 6f 72 64 53 65 61 72 63 68 47 65 6e 65 72 61 74 6f 72 } //1 WordSearchGenerator
		$a_81_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}