
rule Ransom_MSIL_Filecoder_AAW_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.AAW!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 00 69 00 6c 00 65 00 73 00 20 00 48 00 61 00 76 00 65 00 20 00 42 00 65 00 65 00 6e 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 3a 00 29 00 } //2 Files Have Been Encrypted :)
		$a_01_1 = {53 00 65 00 6e 00 64 00 20 00 4d 00 45 00 20 00 53 00 6f 00 6d 00 65 00 20 00 24 00 24 00 24 00 24 00 20 00 6f 00 72 00 20 00 69 00 74 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 64 00 2e 00 } //2 Send ME Some $$$$ or it will be deleted.
		$a_01_2 = {61 6c 70 61 63 69 6e 6f 2e 70 64 62 } //2 alpacino.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}