
rule Trojan_BAT_Androm_NA_MTB{
	meta:
		description = "Trojan:BAT/Androm.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 11 04 11 05 02 08 11 05 58 91 03 11 05 07 5d 91 61 d2 9c 00 11 05 17 58 } //4
		$a_81_1 = {56 65 72 74 65 78 44 61 74 61 } //1 VertexData
		$a_81_2 = {65 6e 63 72 79 70 74 65 64 44 61 74 61 } //1 encryptedData
		$a_81_3 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_4 = {47 65 74 42 79 74 65 73 41 73 79 6e 63 } //1 GetBytesAsync
	condition:
		((#a_01_0  & 1)*4+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=8
 
}