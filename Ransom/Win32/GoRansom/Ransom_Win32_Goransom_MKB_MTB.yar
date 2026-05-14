
rule Ransom_Win32_Goransom_MKB_MTB{
	meta:
		description = "Ransom:Win32/Goransom.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_81_0 = {71 70 39 58 65 30 76 38 5a 7a 74 39 49 77 42 6a 39 5f 57 74 2f 74 69 6c 5a 4a 50 31 65 47 57 79 6c 4c 77 2d 6b 54 4a 75 77 2f 42 71 72 37 49 49 6b 75 36 62 61 6d 65 39 6e 6f 6e 33 55 5a 2f 66 4c 6b 34 61 78 78 39 65 59 6d 5f 77 44 75 36 4a 37 58 6b } //1 qp9Xe0v8Zzt9IwBj9_Wt/tilZJP1eGWylLw-kTJuw/Bqr7IIku6bame9non3UZ/fLk4axx9eYm_wDu6J7Xk
		$a_81_1 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 } //1 main.encrypt
		$a_81_2 = {61 65 73 2e 65 6e 63 72 79 70 74 42 6c 6f 63 6b 47 6f } //1 aes.encryptBlockGo
		$a_81_3 = {64 65 73 2e 65 6e 63 72 79 70 74 42 6c 6f 63 6b } //1 des.encryptBlock
		$a_81_4 = {58 4f 52 4b 65 79 53 74 72 65 61 6d } //1 XORKeyStream
		$a_81_5 = {50 75 62 6c 69 63 4b 65 79 } //5 PublicKey
		$a_81_6 = {67 6f 72 61 6e 73 6f 6d 2e 67 6f } //5 goransom.go
		$a_81_7 = {4c 6f 63 6b } //1 Lock
		$a_81_8 = {6d 61 69 6e 2e 66 75 6e 63 } //1 main.func
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*5+(#a_81_6  & 1)*5+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=17
 
}