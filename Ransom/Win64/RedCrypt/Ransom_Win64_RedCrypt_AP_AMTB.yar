
rule Ransom_Win64_RedCrypt_AP_AMTB{
	meta:
		description = "Ransom:Win64/RedCrypt.AP!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {4f 6f 6f 70 73 21 20 59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 74 72 61 73 68 65 64 20 62 79 20 4d 6f 63 68 61 21 } //Ooops! Your computer has been trashed by Mocha!  1
		$a_80_1 = {41 6e 79 20 61 74 74 65 6d 70 74 73 20 74 6f 20 63 6c 6f 73 65 20 4d 6f 63 68 61 20 77 69 6c 6c 20 62 65 20 64 65 74 65 63 74 65 64 } //Any attempts to close Mocha will be detected  1
		$a_80_2 = {4d 6f 63 68 61 2d 78 36 34 2e 70 64 62 } //Mocha-x64.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}