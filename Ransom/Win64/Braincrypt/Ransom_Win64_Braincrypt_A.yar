
rule Ransom_Win64_Braincrypt_A{
	meta:
		description = "Ransom:Win64/Braincrypt.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 72 61 69 6e 63 72 79 70 74 2e 67 6f } //1 braincrypt.go
		$a_01_1 = {2f 67 61 74 65 77 61 79 2f 67 61 74 65 2e 70 68 70 } //1 /gateway/gate.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}