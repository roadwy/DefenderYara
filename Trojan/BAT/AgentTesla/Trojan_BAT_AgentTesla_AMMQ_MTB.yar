
rule Trojan_BAT_AgentTesla_AMMQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_81_1 = {47 65 74 4f 62 6a 65 63 74 } //01 00  GetObject
		$a_81_2 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_81_3 = {43 6f 6e 73 74 41 72 72 61 79 } //01 00  ConstArray
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_5 = {5a 65 72 6f 4f 72 4d 69 6e 75 73 } //01 00  ZeroOrMinus
		$a_81_6 = {4d 75 6c 74 69 63 61 73 74 53 75 70 70 6f 72 74 } //01 00  MulticastSupport
		$a_81_7 = {38 66 35 35 34 66 35 34 2d 65 66 39 33 2d 34 30 31 63 2d 61 37 34 66 2d 32 61 66 32 33 64 37 62 61 36 35 63 } //00 00  8f554f54-ef93-401c-a74f-2af23d7ba65c
	condition:
		any of ($a_*)
 
}