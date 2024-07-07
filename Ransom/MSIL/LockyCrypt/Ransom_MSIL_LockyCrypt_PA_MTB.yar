
rule Ransom_MSIL_LockyCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/LockyCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 00 6c 00 6f 00 63 00 6b 00 79 00 } //1 .locky
		$a_01_1 = {5b 00 4c 00 6f 00 63 00 6b 00 54 00 58 00 54 00 46 00 69 00 6c 00 65 00 73 00 5d 00 } //1 [LockTXTFiles]
		$a_01_2 = {4e 00 6f 00 74 00 20 00 79 00 65 00 74 00 20 00 70 00 61 00 79 00 20 00 42 00 54 00 43 00 41 00 6d 00 6f 00 75 00 6e 00 74 00 3d 00 } //1 Not yet pay BTCAmount=
		$a_01_3 = {46 00 49 00 4c 00 45 00 20 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 20 00 42 00 59 00 20 00 4b 00 45 00 4c 00 4c 00 59 00 } //1 FILE ENCRYPTED BY KELLY
		$a_01_4 = {5c 4c 65 65 6e 2e 70 64 62 } //1 \Leen.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}