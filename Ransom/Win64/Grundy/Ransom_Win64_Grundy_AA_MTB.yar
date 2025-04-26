
rule Ransom_Win64_Grundy_AA_MTB{
	meta:
		description = "Ransom:Win64/Grundy.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 3a 2f 74 65 73 74 2f 72 65 70 6f 73 2f 53 6d 61 6c 6c 43 72 79 70 74 6f 41 70 70 2f 57 69 6e 2f 45 6e 43 72 79 70 74 6f 72 2f 54 45 4d 50 2f 6d 61 69 6e 2e 67 6f } //10 K:/test/repos/SmallCryptoApp/Win/EnCryptor/TEMP/main.go
		$a_01_1 = {65 6e 63 6f 64 69 6e 67 2f 61 73 6e 31 2e 70 61 72 73 65 42 61 73 65 31 32 38 49 6e 74 } //1 encoding/asn1.parseBase128Int
		$a_01_2 = {63 72 79 70 74 6f 2f 65 6c 6c 69 70 74 69 63 2e 62 69 67 46 72 6f 6d 48 65 78 } //1 crypto/elliptic.bigFromHex
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}