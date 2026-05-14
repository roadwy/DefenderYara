
rule Ransom_Win64_Kyber_A{
	meta:
		description = "Ransom:Win64/Kyber.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 53 65 72 76 69 63 65 20 43 6f 6e 74 72 6f 6c 20 4d 61 6e 61 67 65 72 } //1 Failed to open Service Control Manager
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 73 65 74 20 76 61 6c 75 65 20 66 6f 72 20 66 69 6c 65 20 65 78 74 65 6e 73 69 6f 6e 20 6b 65 79 3a } //1 Failed to set value for file extension key:
		$a_01_2 = {4b 69 6c 6c 69 6e 67 20 4d 69 63 72 6f 73 6f 66 74 20 48 79 70 65 72 2d 56 20 6d 61 63 68 69 6e 65 73 2e 2e } //1 Killing Microsoft Hyper-V machines..
		$a_01_3 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 65 6e 63 72 79 70 74 65 64 } //1 Successfully encrypted
		$a_01_4 = {45 72 72 6f 72 20 77 68 65 6e 20 74 72 79 69 6e 67 20 74 6f 20 63 61 6c 63 20 4b 79 62 65 72 20 28 63 69 70 68 65 72 74 65 78 74 2c 20 73 68 61 72 65 64 5f 73 65 63 72 65 74 29 } //1 Error when trying to calc Kyber (ciphertext, shared_secret)
		$a_01_5 = {45 72 72 6f 72 20 77 68 69 6c 65 20 63 72 65 61 74 69 6e 67 20 6e 6f 74 65 20 66 69 6c 65 3a } //1 Error while creating note file:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}