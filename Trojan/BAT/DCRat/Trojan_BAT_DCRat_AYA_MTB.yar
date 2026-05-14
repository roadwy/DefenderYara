
rule Trojan_BAT_DCRat_AYA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {1f 10 8d 42 00 00 01 0d 07 09 16 1f 10 6f 3f 00 00 0a 26 08 09 6f 8a 00 00 0a 00 07 08 6f 8b 00 00 0a 16 73 82 00 00 0a 13 08 00 07 6f 8c 00 00 0a 1f 10 6a 59 17 6a 58 d4 8d 42 00 00 01 13 09 11 08 11 09 16 11 09 8e 69 6f 3f 00 00 0a 8d 42 00 00 01 13 0a 11 09 16 11 0a 16 11 0a 8e 69 28 8d 00 00 0a 00 11 0a 13 0b de 23 } //7
		$a_01_1 = {45 6e 63 6f 64 65 32 42 79 74 65 73 } //2 Encode2Bytes
		$a_01_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_3 = {44 65 63 6f 64 65 46 72 6f 6d 42 79 74 65 73 } //1 DecodeFromBytes
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}