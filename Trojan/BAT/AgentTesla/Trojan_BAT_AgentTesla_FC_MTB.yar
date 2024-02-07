
rule Trojan_BAT_AgentTesla_FC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 03 50 02 04 28 90 01 03 06 04 28 10 00 00 0a 17 15 16 28 11 00 00 0a 90 00 } //01 00 
		$a_01_1 = {51 00 de 08 26 00 05 17 52 00 de 00 2a } //01 00 
		$a_81_2 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_3 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_4 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_5 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_81_6 = {47 65 74 54 79 } //01 00  GetTy
		$a_81_7 = {45 6e 74 72 79 50 } //00 00  EntryP
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_FC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0d 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 66 38 37 38 37 62 61 31 2d 63 30 35 30 2d 34 62 34 37 2d 61 64 65 30 2d 33 34 39 62 39 34 31 31 37 63 64 64 } //14 00  $f8787ba1-c050-4b47-ade0-349b94117cdd
		$a_81_1 = {24 66 31 63 62 36 36 34 61 2d 61 64 37 31 2d 34 62 31 35 2d 61 64 63 33 2d 30 64 30 66 66 34 32 30 66 38 34 30 } //14 00  $f1cb664a-ad71-4b15-adc3-0d0ff420f840
		$a_81_2 = {24 39 61 64 38 39 61 66 39 2d 39 66 35 39 2d 34 39 30 32 2d 38 62 65 31 2d 30 61 36 32 61 66 30 62 62 37 33 35 } //14 00  $9ad89af9-9f59-4902-8be1-0a62af0bb735
		$a_81_3 = {24 34 38 36 34 38 61 65 37 2d 38 39 32 33 2d 34 31 35 38 2d 61 62 34 34 2d 38 30 66 33 30 34 31 62 30 33 37 32 } //01 00  $48648ae7-8923-4158-ab44-80f3041b0372
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_9 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_12 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}