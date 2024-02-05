
rule Ransom_Win64_FileCryptor_C_MTB{
	meta:
		description = "Ransom:Win64/FileCryptor.C!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 69 67 73 61 77 2d 72 61 6e 73 6f 6d 77 61 72 65 } //01 00 
		$a_01_1 = {62 69 74 73 61 64 6d 69 6e 20 2f 74 72 61 6e 73 66 65 72 20 6d 79 64 6f 77 6e 6c 6f 61 64 6a 6f 62 20 2f 64 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_01_2 = {72 65 67 20 61 64 64 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 20 2f 76 20 57 61 6c 6c 70 61 70 65 72 } //01 00 
		$a_01_3 = {44 65 63 72 79 70 74 69 6e 67 20 79 6f 75 72 20 66 69 6c 65 73 20 6e 6f 77 21 } //00 00 
	condition:
		any of ($a_*)
 
}