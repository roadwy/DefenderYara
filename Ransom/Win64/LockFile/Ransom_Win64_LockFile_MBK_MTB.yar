
rule Ransom_Win64_LockFile_MBK_MTB{
	meta:
		description = "Ransom:Win64/LockFile.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 } //winsta0\default  1
		$a_80_1 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //YOUR FILES ARE ENCRYPTED  1
		$a_80_2 = {54 68 65 20 70 72 69 63 65 20 6f 66 20 64 65 63 72 79 70 74 69 6f 6e 20 73 6f 66 74 77 61 72 65 20 69 73 } //The price of decryption software is  1
		$a_80_3 = {57 65 20 6f 6e 6c 79 20 61 63 63 65 70 74 20 42 69 74 63 6f 69 6e 20 70 61 79 6d 65 6e 74 } //We only accept Bitcoin payment  1
		$a_02_4 = {52 00 45 00 41 00 44 00 4d 00 45 00 2d 00 46 00 49 00 4c 00 45 00 90 02 20 2e 00 68 00 74 00 61 00 90 00 } //1
		$a_02_5 = {52 45 41 44 4d 45 2d 46 49 4c 45 90 02 20 2e 68 74 61 90 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}