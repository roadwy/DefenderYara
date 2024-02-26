
rule Trojan_BAT_RedlineStealer_PSAO_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.PSAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 55 a2 0b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 68 00 00 00 70 07 00 00 7a 00 00 00 87 3a 00 00 91 00 } //01 00 
		$a_01_1 = {6e 4f 70 43 6f 4f 70 43 6f 4f 70 43 6f 4f 30 43 6f } //01 00  nOpCoOpCoOpCoO0Co
		$a_01_2 = {35 6e 4f 70 63 6f 4f 70 3b 6e 4f 70 41 6f 4f 70 43 6f 4f 70 43 6f 4f 70 43 6f 4f 50 43 6f 2f } //01 00  5nOpcoOp;nOpAoOpCoOpCoOpCoOPCo/
		$a_01_3 = {43 52 4f 57 43 6f 4f 70 43 6f 4f } //01 00  CROWCoOpCoO
		$a_01_4 = {59 40 28 4b 35 } //01 00  Y@(K5
		$a_01_5 = {40 7e 40 28 77 } //01 00  @~@(w
		$a_01_6 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 48 4d 41 43 4d 44 35 } //00 00  System.Security.Cryptography.HMACMD5
	condition:
		any of ($a_*)
 
}