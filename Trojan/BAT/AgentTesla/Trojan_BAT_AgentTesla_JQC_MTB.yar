
rule Trojan_BAT_AgentTesla_JQC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 0e 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4e 65 57 63 4f 50 68 61 72 65 } //0a 00  NeWcOPhare
		$a_01_1 = {67 66 67 66 64 66 64 67 } //0a 00  gfgfdfdg
		$a_01_2 = {66 64 73 66 64 73 } //01 00  fdsfds
		$a_01_3 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //01 00  LzmaDecoder
		$a_01_4 = {6d 5f 49 73 4d 61 74 63 68 44 65 63 6f 64 65 72 73 } //01 00  m_IsMatchDecoders
		$a_00_5 = {43 6f 70 79 42 6c 6f 63 6b 00 50 75 74 42 79 74 65 00 47 65 74 42 79 74 65 } //01 00 
		$a_01_6 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_7 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_01_8 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00  Decompress
		$a_01_9 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //01 00  ReverseDecode
		$a_01_10 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_11 = {42 69 74 44 65 63 6f 64 65 72 } //01 00  BitDecoder
		$a_01_12 = {42 69 74 54 72 65 65 44 65 63 6f 64 65 72 } //01 00  BitTreeDecoder
		$a_01_13 = {44 65 63 6f 64 65 44 69 72 65 63 74 42 69 74 73 } //00 00  DecodeDirectBits
	condition:
		any of ($a_*)
 
}