
rule Ransom_Win64_Genasom_AR_MTB{
	meta:
		description = "Ransom:Win64/Genasom.AR!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 } //1 main.encrypt
		$a_01_1 = {43 3a 2f 55 73 65 72 73 2f 77 69 6e 64 6f 77 73 2f 67 6f 2f 73 72 63 2f 56 61 73 68 52 61 6e 73 6f 6d 77 61 72 65 76 32 2f 45 6e 63 72 79 70 74 2e 67 6f } //10 C:/Users/windows/go/src/VashRansomwarev2/Encrypt.go
		$a_01_2 = {64 65 63 72 79 70 74 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 66 74 65 72 20 70 61 79 69 6e 67 20 74 68 65 20 72 61 6e 73 6f 6d } //1 decrypt all your files after paying the ransom
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=12
 
}