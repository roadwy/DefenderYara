
rule Ransom_MSIL_Crilock_A{
	meta:
		description = "Ransom:MSIL/Crilock.A,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 6f 6e 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 3a 20 70 68 6f 74 6f 73 2c 20 76 69 64 65 6f 73 2c 20 64 6f 63 75 6d 65 6e 74 73 2c } //1 Your important files on this computer were encrypted: photos, videos, documents,
		$a_01_1 = {79 6f 75 20 6e 65 65 64 20 74 6f 20 70 61 79 20 33 30 30 20 55 53 44 20 2f 20 45 55 52 20 2f 20 73 69 6d 69 6c 61 72 20 61 6d 6f 75 6e 74 20 69 6e 20 42 69 74 63 6f 69 6e 2e 0a 0a 43 6c 69 63 } //1
		$a_01_2 = {2e 72 65 73 6f 75 72 63 65 73 00 6d 73 75 6e 65 74 2e 66 72 6d 35 2e 72 65 73 6f 75 72 63 65 73 00 6d 73 75 6e 65 74 2e 66 72 6d 32 2e 72 65 73 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=2
 
}