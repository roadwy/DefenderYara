
rule Ransom_MSIL_Swagkarna_MTB{
	meta:
		description = "Ransom:MSIL/Swagkarna!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 79 00 50 00 72 00 69 00 76 00 61 00 74 00 65 00 4b 00 65 00 79 00 } //01 00  MyPrivateKey
		$a_01_1 = {2e 00 73 00 77 00 61 00 67 00 6b 00 61 00 72 00 6e 00 61 00 } //01 00  .swagkarna
		$a_01_2 = {63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 3a 00 } //01 00  crypted :
		$a_01_3 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 } //01 00  C:\Users\
		$a_01_4 = {2e 00 70 00 6e 00 67 00 } //01 00  .png
		$a_01_5 = {2e 00 68 00 74 00 6d 00 6c 00 } //01 00  .html
		$a_01_6 = {2e 00 63 00 70 00 70 00 } //01 00  .cpp
		$a_01_7 = {2e 00 74 00 78 00 74 00 } //00 00  .txt
	condition:
		any of ($a_*)
 
}