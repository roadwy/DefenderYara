
rule Trojan_BAT_Rozena_RPQ_MTB{
	meta:
		description = "Trojan:BAT/Rozena.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 50 6c 61 6e 54 6f 6f 6c 73 } //01 00  ZPlanTools
		$a_01_1 = {5a 50 6c 61 6e 44 65 6d 6f } //01 00  ZPlanDemo
		$a_01_2 = {47 65 74 43 6f 63 65 } //01 00  GetCoce
		$a_01_3 = {47 65 74 46 69 6c 65 4e 75 6d } //01 00  GetFileNum
		$a_01_4 = {52 53 41 44 65 63 72 79 70 74 } //01 00  RSADecrypt
		$a_01_5 = {44 45 6e 63 72 79 70 74 69 6f 6e } //01 00  DEncryption
		$a_01_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_7 = {43 72 65 61 74 65 54 68 72 65 61 64 } //01 00  CreateThread
		$a_01_8 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //01 00  WaitForSingleObject
		$a_01_9 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_01_10 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_11 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_12 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_13 = {3c 00 52 00 53 00 41 00 4b 00 65 00 79 00 56 00 61 00 6c 00 75 00 65 00 3e 00 } //01 00  <RSAKeyValue>
		$a_01_14 = {3c 00 45 00 78 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 3e 00 } //01 00  <Exponent>
		$a_01_15 = {3c 00 49 00 6e 00 76 00 65 00 72 00 73 00 65 00 51 00 3e 00 } //00 00  <InverseQ>
	condition:
		any of ($a_*)
 
}