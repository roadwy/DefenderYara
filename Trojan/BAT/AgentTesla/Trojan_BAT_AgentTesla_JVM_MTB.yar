
rule Trojan_BAT_AgentTesla_JVM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 42 31 32 31 43 30 33 34 2d 41 34 37 37 2d 34 45 46 46 2d 38 46 39 32 2d 44 39 41 39 38 30 46 39 37 44 42 31 } //01 00  $B121C034-A477-4EFF-8F92-D9A980F97DB1
		$a_01_1 = {50 55 42 47 20 43 4f 52 50 4f 52 41 54 49 4f 4e } //01 00  PUBG CORPORATION
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_01_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_01_5 = {47 65 74 43 68 61 72 } //01 00  GetChar
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_7 = {00 43 68 72 57 00 } //01 00  䌀牨W
		$a_01_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_01_10 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}