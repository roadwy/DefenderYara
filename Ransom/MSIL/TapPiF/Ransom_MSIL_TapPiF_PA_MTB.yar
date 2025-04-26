
rule Ransom_MSIL_TapPiF_PA_MTB{
	meta:
		description = "Ransom:MSIL/TapPiF.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {4f 6f 6f 70 73 21 20 59 6f 75 72 20 53 6f 6d 65 20 46 69 6c 65 73 20 48 61 73 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 21 } //1 Ooops! Your Some Files Has Been Encrypted!
		$a_81_1 = {59 6f 75 72 20 43 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 69 6e 6a 65 63 74 65 64 20 62 79 20 54 61 70 52 69 46 20 54 72 6f 6a 61 6e 73 21 } //1 Your Computer has been injected by TapRiF Trojans!
		$a_81_2 = {32 34 37 38 32 39 30 2e 62 61 74 } //1 2478290.bat
		$a_81_3 = {50 61 79 20 4e 6f 77 2c 20 49 66 20 59 6f 75 20 57 61 6e 6e 61 20 74 6f 20 44 65 63 72 79 70 74 20 59 6f 75 72 20 61 6c 6c 20 66 69 6c 65 73 21 } //1 Pay Now, If You Wanna to Decrypt Your all files!
		$a_03_4 = {5c 00 54 00 61 00 70 00 50 00 69 00 46 00 5c 00 6f 00 62 00 6a 00 5c 00 [0-10] 5c 00 54 00 61 00 70 00 50 00 69 00 46 00 2e 00 70 00 64 00 62 00 } //1
		$a_03_5 = {5c 54 61 70 50 69 46 5c 6f 62 6a 5c [0-10] 5c 54 61 70 50 69 46 2e 70 64 62 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}