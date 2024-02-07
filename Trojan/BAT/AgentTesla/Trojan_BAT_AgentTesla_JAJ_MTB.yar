
rule Trojan_BAT_AgentTesla_JAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 0c 00 00 0a 00 "
		
	strings :
		$a_02_0 = {70 0b 06 8e 69 17 59 0c 2b 19 00 07 06 08 8f 90 01 03 01 28 90 01 03 0a 28 90 01 03 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df 90 00 } //0a 00 
		$a_02_1 = {0b 00 07 0c 16 0d 2b 1c 08 09 9a 13 04 00 06 11 04 1f 10 28 90 01 03 0a d1 6f 90 01 03 0a 26 00 09 17 58 0d 09 08 8e 69 32 de 90 00 } //14 00 
		$a_81_2 = {61 34 65 34 35 30 61 31 2d 63 64 30 38 2d 34 30 62 64 2d 39 61 61 65 2d 34 39 64 64 38 30 64 66 30 38 63 35 } //01 00  a4e450a1-cd08-40bd-9aae-49dd80df08c5
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_81_4 = {53 70 6c 69 74 } //01 00  Split
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_6 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_7 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_8 = {46 75 6e 63 74 69 6f 6e 49 6e 69 74 } //01 00  FunctionInit
		$a_81_9 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_10 = {54 65 74 72 69 73 } //01 00  Tetris
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}