
rule Trojan_BAT_AgentTesla_JYA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 36 34 62 32 66 62 65 2d 34 65 38 34 2d 34 66 32 66 2d 39 34 36 33 2d 63 33 65 37 34 33 32 35 38 65 65 31 } //01 00  c64b2fbe-4e84-4f2f-9463-c3e743258ee1
		$a_01_1 = {44 61 74 61 41 63 63 65 73 73 } //01 00  DataAccess
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //00 00  DebuggerBrowsableState
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_JYA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.JYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 6f 69 00 67 73 64 66 2e 65 78 } //01 00 
		$a_01_1 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //01 00  LzmaDecoder
		$a_01_2 = {6d 5f 49 73 4d 61 74 63 68 44 65 63 6f 64 65 72 73 } //01 00  m_IsMatchDecoders
		$a_00_3 = {43 6f 70 79 42 6c 6f 63 6b 00 50 75 74 42 79 74 65 00 47 65 74 42 79 74 65 } //01 00 
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_5 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_01_6 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00  Decompress
		$a_01_7 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //01 00  ReverseDecode
		$a_01_8 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_9 = {42 69 74 44 65 63 6f 64 65 72 } //01 00  BitDecoder
		$a_01_10 = {42 69 74 54 72 65 65 44 65 63 6f 64 65 72 } //01 00  BitTreeDecoder
		$a_01_11 = {44 65 63 6f 64 65 44 69 72 65 63 74 42 69 74 73 } //00 00  DecodeDirectBits
	condition:
		any of ($a_*)
 
}