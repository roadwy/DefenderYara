
rule Trojan_BAT_Androm_DA_MTB{
	meta:
		description = "Trojan:BAT/Androm.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_00_0 = {01 57 17 a2 09 09 0b 00 00 00 5a a4 01 00 16 00 00 01 00 00 00 5e 00 00 00 1b 00 00 00 35 00 00 00 65 } //3
		$a_01_1 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //3 HttpWebResponse
		$a_01_2 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //3 System.Security.Cryptography
		$a_00_3 = {54 00 72 00 69 00 70 00 6c 00 65 00 44 00 45 00 53 00 } //3 TripleDES
		$a_00_4 = {52 00 69 00 6a 00 6e 00 64 00 61 00 65 00 6c 00 } //3 Rijndael
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //3 CreateDecryptor
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}