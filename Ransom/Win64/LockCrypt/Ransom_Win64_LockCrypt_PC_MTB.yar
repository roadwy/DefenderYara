
rule Ransom_Win64_LockCrypt_PC_MTB{
	meta:
		description = "Ransom:Win64/LockCrypt.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {47 45 4e 42 4f 54 49 44 } //GENBOTID  1
		$a_80_1 = {52 45 41 44 4d 45 5f 46 4f 52 5f 44 45 43 52 59 50 54 2e 74 78 74 } //README_FOR_DECRYPT.txt  1
		$a_80_2 = {2f 42 6e 79 61 72 38 52 73 4b 30 34 75 67 } ///Bnyar8RsK04ug  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}