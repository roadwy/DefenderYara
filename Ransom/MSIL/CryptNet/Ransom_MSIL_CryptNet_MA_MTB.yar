
rule Ransom_MSIL_CryptNet_MA_MTB{
	meta:
		description = "Ransom:MSIL/CryptNet.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 0e 18 5b 02 8e 69 18 5b 11 09 5a 59 13 10 } //02 00 
		$a_01_1 = {39 64 64 66 39 64 33 65 2d 66 36 61 37 2d 34 64 35 39 2d 39 39 61 35 2d 66 34 35 30 34 66 65 66 35 32 62 38 } //02 00 
		$a_01_2 = {6f 32 62 37 65 4e 56 6a 59 4a 34 67 71 73 45 6f 6f 75 6a 2e 53 51 4f 77 68 6a 56 66 72 78 57 45 72 50 36 6a 56 58 61 } //02 00 
		$a_01_3 = {57 b5 02 3c 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 8d 00 00 00 24 } //00 00 
	condition:
		any of ($a_*)
 
}