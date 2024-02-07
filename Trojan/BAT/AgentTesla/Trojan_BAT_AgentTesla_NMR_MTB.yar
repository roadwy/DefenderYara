
rule Trojan_BAT_AgentTesla_NMR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 02 06 16 06 90 0a 13 00 20 00 10 00 00 8d 90 01 01 00 00 01 90 02 08 8e 69 6f 90 01 03 0a 0b 07 16 30 01 2a 03 06 16 07 6f 90 01 03 0a 2b e4 90 00 } //01 00 
		$a_03_1 = {08 07 5d 91 0d 0e 04 08 0e 05 58 03 08 04 58 91 02 6f 90 01 03 0a 09 06 5d 91 61 d2 9c 08 17 58 0c 08 05 32 d5 90 00 } //01 00 
		$a_01_2 = {52 00 69 00 6a 00 6e 00 64 00 61 00 65 00 6c 00 00 07 52 00 43 00 32 } //01 00 
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_5 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_6 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_8 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_9 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_10 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_11 = {44 65 71 75 65 75 65 } //01 00  Dequeue
		$a_01_12 = {45 6e 71 75 65 75 65 } //01 00  Enqueue
		$a_01_13 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}