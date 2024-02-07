
rule Ransom_MSIL_CryptoJoker_SN_MTB{
	meta:
		description = "Ransom:MSIL/CryptoJoker.SN!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 46 69 6c 65 46 75 6c 6c 79 } //01 00  EncryptFileFully
		$a_01_1 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 29 00 20 00 26 00 26 00 20 00 28 00 64 00 65 00 6c 00 20 00 2f 00 51 00 } //01 00  127.0.0.1) && (del /Q
		$a_01_2 = {43 00 3a 00 2f 00 55 00 73 00 65 00 72 00 73 00 2f 00 55 00 73 00 65 00 72 00 2f 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2f 00 4d 00 42 00 52 00 2d 00 4b 00 69 00 6c 00 6c 00 2d 00 6d 00 61 00 73 00 74 00 65 00 72 00 2f 00 4d 00 42 00 52 00 } //01 00  C:/Users/User/Desktop/MBR-Kill-master/MBR
		$a_01_3 = {6a 00 6f 00 6b 00 69 00 6e 00 67 00 77 00 69 00 74 00 68 00 79 00 6f 00 75 00 2e 00 63 00 72 00 79 00 70 00 74 00 6f 00 6a 00 6f 00 6b 00 65 00 72 00 } //00 00  jokingwithyou.cryptojoker
	condition:
		any of ($a_*)
 
}