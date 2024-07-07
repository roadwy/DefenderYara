
rule Ransom_MSIL_Thanos_DC_MTB{
	meta:
		description = "Ransom:MSIL/Thanos.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 6f 72 6b 65 72 43 72 79 70 74 65 72 32 } //1 WorkerCrypter2
		$a_81_1 = {45 6e 63 72 79 70 74 32 } //1 Encrypt2
		$a_81_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_3 = {44 65 63 6f 64 65 48 75 66 66 6d 61 6e } //1 DecodeHuffman
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}