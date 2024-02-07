
rule Trojan_BAT_AgentTesla_LRB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 47 65 74 50 69 78 65 6c 00 } //01 00  䜀瑥楐數l
		$a_01_1 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_2 = {00 43 46 33 34 32 34 32 33 35 36 36 35 00 } //01 00  䌀㍆㈴㈴㔳㘶5
		$a_01_3 = {00 4c 65 76 65 6c 00 } //01 00 
		$a_01_4 = {00 43 46 30 30 31 32 33 31 00 } //01 00 
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_7 = {00 43 46 32 33 34 30 35 32 00 } //01 00  䌀㉆㐳㔰2
		$a_01_8 = {00 43 46 33 32 31 34 38 31 32 33 00 } //01 00  䌀㍆ㄲ㠴㈱3
		$a_01_9 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //00 00  GetTypeFromHandle
	condition:
		any of ($a_*)
 
}