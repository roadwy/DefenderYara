
rule Ransom_MSIL_Birbware_A{
	meta:
		description = "Ransom:MSIL/Birbware.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 62 00 69 00 72 00 62 00 2e 00 70 00 6e 00 67 } //1
		$a_01_1 = {5c 72 61 6e 73 6f 6d 2e 70 64 62 } //1 \ransom.pdb
		$a_01_2 = {61 00 70 00 61 00 6f 00 77 00 6a 00 64 00 73 00 6f 00 64 00 69 00 75 00 6a 00 39 00 28 00 2f 00 29 00 3d 00 28 00 2f 00 31 00 34 00 6a 00 6c 00 71 00 6b 00 73 00 6a 00 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}