
rule TrojanSpy_BAT_keylogger_ABZ_MTB{
	meta:
		description = "TrojanSpy:BAT/keylogger.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {07 07 6f 8c 00 00 0a 07 6f 8d 00 00 0a 6f 78 00 00 0a 0c 04 73 8e 00 00 0a 0d 09 08 16 73 8f 00 00 0a 13 04 11 04 06 16 06 8e 69 6f 92 00 00 0a 26 de 0c 11 04 2c 07 11 04 6f 24 00 00 0a dc } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}