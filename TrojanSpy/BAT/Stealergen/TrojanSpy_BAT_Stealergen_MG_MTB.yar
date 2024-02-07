
rule TrojanSpy_BAT_Stealergen_MG_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 73 64 76 73 64 76 64 73 76 73 64 } //01 00  vsdvsdvdsvsd
		$a_01_1 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00  Decompress
		$a_01_2 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_4 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //01 00  ReverseDecode
		$a_01_5 = {44 65 63 6f 64 65 57 69 74 68 4d 61 74 63 68 42 79 74 65 } //01 00  DecodeWithMatchByte
		$a_01_6 = {47 65 74 53 74 61 74 65 } //01 00  GetState
		$a_01_7 = {46 6c 75 73 68 } //01 00  Flush
		$a_01_8 = {4e 6f 6e 20 4f 62 66 75 73 63 61 74 65 64 } //01 00  Non Obfuscated
		$a_01_9 = {49 73 43 68 61 72 53 74 61 74 65 } //01 00  IsCharState
		$a_01_10 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_11 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_12 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_13 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //00 00  MemoryStream
	condition:
		any of ($a_*)
 
}