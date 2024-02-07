
rule Ransom_MSIL_BearCrypt_SK_MTB{
	meta:
		description = "Ransom:MSIL/BearCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {42 65 61 72 2e 65 78 65 } //01 00  Bear.exe
		$a_01_1 = {66 75 57 69 6e 49 6e 69 } //01 00  fuWinIni
		$a_01_2 = {52 53 41 45 6e 63 72 79 70 74 } //01 00  RSAEncrypt
		$a_01_3 = {41 45 53 45 6e 63 72 79 70 74 } //01 00  AESEncrypt
		$a_01_4 = {65 6e 63 72 79 70 74 53 74 72 } //01 00  encryptStr
		$a_01_5 = {4d 61 4d 6f 34 33 34 33 37 36 20 50 72 6f 74 65 63 74 6f 72 } //00 00  MaMo434376 Protector
	condition:
		any of ($a_*)
 
}