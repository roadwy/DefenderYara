
rule Ransom_Win32_Goransom_MKA_MTB{
	meta:
		description = "Ransom:Win32/Goransom.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 08 00 00 "
		
	strings :
		$a_81_0 = {36 46 4b 72 61 69 79 74 5f 77 4c 67 63 36 67 75 42 6f 4a 73 2f 54 36 6b 39 30 47 34 48 39 46 41 74 6f 61 4a 4b 5a 46 6b 78 2f 37 32 4f 5a 4f 32 64 76 58 61 65 4e 39 7a 2d 66 6f 38 4e 53 2f 78 53 56 71 66 71 69 4c 30 61 63 35 77 32 52 50 68 6e 57 41 } //1 6FKraiyt_wLgc6guBoJs/T6k90G4H9FAtoaJKZFkx/72OZO2dvXaeN9z-fo8NS/xSVqfqiL0ac5w2RPhnWA
		$a_81_1 = {45 6e 63 72 79 70 74 } //1 Encrypt
		$a_81_2 = {61 65 73 2e 65 6e 63 72 79 70 74 42 6c 6f 63 6b 47 6f } //1 aes.encryptBlockGo
		$a_81_3 = {45 6e 63 72 79 70 74 2e 73 74 6b 6f 62 6a } //1 Encrypt.stkobj
		$a_81_4 = {67 6f 72 61 6e 73 6f 6d 2f 75 74 69 6c 73 2e 45 6e 63 72 79 70 74 } //5 goransom/utils.Encrypt
		$a_81_5 = {63 69 70 68 65 72 2e 4e 65 77 43 46 42 44 65 63 72 79 70 74 65 72 } //1 cipher.NewCFBDecrypter
		$a_81_6 = {67 6f 72 61 6e 73 6f 6d 2e 67 6f } //5 goransom.go
		$a_81_7 = {6d 61 69 6e 2e 72 61 6e 73 6f 6d 77 61 72 65 } //5 main.ransomware
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*5+(#a_81_5  & 1)*1+(#a_81_6  & 1)*5+(#a_81_7  & 1)*5) >=20
 
}