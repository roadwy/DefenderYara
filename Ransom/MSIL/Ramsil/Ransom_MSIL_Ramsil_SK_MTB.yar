
rule Ransom_MSIL_Ramsil_SK_MTB{
	meta:
		description = "Ransom:MSIL/Ramsil.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 \Desktop\README.txt
		$a_01_1 = {54 00 68 00 69 00 73 00 20 00 69 00 73 00 20 00 61 00 20 00 70 00 75 00 6e 00 69 00 73 00 68 00 6d 00 65 00 6e 00 74 00 20 00 6f 00 6e 00 20 00 79 00 6f 00 75 00 20 00 21 00 21 00 21 00 } //1 This is a punishment on you !!!
		$a_01_2 = {46 00 69 00 6c 00 65 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 61 00 72 00 65 00 20 00 61 00 73 00 20 00 66 00 6f 00 6c 00 6c 00 6f 00 77 00 73 00 3a 00 } //1 Files encrypted are as follows:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}