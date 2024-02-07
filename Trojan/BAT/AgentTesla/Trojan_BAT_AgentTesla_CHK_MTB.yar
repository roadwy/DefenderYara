
rule Trojan_BAT_AgentTesla_CHK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 49 49 49 49 49 49 49 32 } //01 00  IIIIIIII2
		$a_01_1 = {49 49 49 49 49 49 49 49 49 35 } //01 00  IIIIIIIII5
		$a_01_2 = {49 49 49 49 49 49 49 49 49 49 31 } //01 00  IIIIIIIIII1
		$a_01_3 = {49 49 49 49 49 49 49 49 49 49 49 33 } //01 00  IIIIIIIIIII3
		$a_01_4 = {49 49 49 49 49 49 49 49 49 49 49 49 49 49 34 } //01 00  IIIIIIIIIIIIII4
		$a_01_5 = {58 5f 31 32 33 31 32 33 34 35 34 33 36 33 } //01 00  X_123123454363
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_7 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_01_8 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_9 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_01_10 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_11 = {4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //01 00  OffsetMarshaler
		$a_01_12 = {52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //00 00  ReturnMessage
	condition:
		any of ($a_*)
 
}