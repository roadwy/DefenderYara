
rule Ransom_Linux_LockBit_B_MTB{
	meta:
		description = "Ransom:Linux/LockBit.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5a 5c 50 4f 5c 19 5f 50 57 5c 4a 19 5f 4b 56 54 19 4d 51 5c 19 5e 56 4f 5c 4b 57 54 5c 57 4d 19 4a 4c 5a 51 19 58 4a 19 4d 51 5c 19 7e 7d 6b 69 19 58 57 5d 19 54 58 57 40 19 56 4d 51 5c 4b 4a 15 19 40 56 4c 19 5a 58 57 19 5b 5c 19 4a 4c 5c 5d 19 5b 40 19 5a 4c } //1
		$a_01_1 = {72 65 73 74 6f 72 65 2d 6d 79 2d 66 69 6c 65 73 2e 74 78 74 } //1 restore-my-files.txt
		$a_01_2 = {62 6f 6f 74 73 65 63 74 2e 62 61 6b } //1 bootsect.bak
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}