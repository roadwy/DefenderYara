
rule Trojan_BAT_AgentTesla_BP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_81_0 = {62 79 74 65 73 54 6f 44 65 63 6f 6d 70 72 65 73 73 } //01 00  bytesToDecompress
		$a_81_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_2 = {46 69 6c 6c 52 65 63 74 61 } //01 00  FillRecta
		$a_81_3 = {41 73 73 6f 63 69 61 74 65 73 } //01 00  Associates
		$a_81_4 = {43 6f 6c 6f 72 43 6f 6e 76 65 72 74 65 72 } //01 00  ColorConverter
		$a_81_5 = {52 65 73 74 72 69 63 74 65 64 45 72 72 6f 72 } //01 00  RestrictedError
		$a_81_6 = {54 61 73 6b 43 61 6e 63 65 6c 65 64 45 78 63 65 70 74 69 6f 6e } //01 00  TaskCanceledException
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_8 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_81_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_10 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_11 = {56 61 6c 75 65 45 6e 75 6d 65 72 61 74 6f 72 } //01 00  ValueEnumerator
		$a_81_12 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_13 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}