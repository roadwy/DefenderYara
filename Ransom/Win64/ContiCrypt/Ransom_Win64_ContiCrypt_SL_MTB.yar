
rule Ransom_Win64_ContiCrypt_SL_MTB{
	meta:
		description = "Ransom:Win64/ContiCrypt.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 65 79 20 67 75 79 73 2c 20 77 65 27 76 65 20 67 6f 74 20 6d 6f 72 65 20 74 68 61 6e 20 32 20 54 62 20 6f 66 20 79 6f 75 72 20 64 61 74 61 } //1 Hey guys, we've got more than 2 Tb of your data
		$a_01_1 = {64 65 6c 65 74 65 64 20 61 6c 6c 20 79 6f 75 72 20 62 61 63 6b 75 70 73 20 61 6e 64 20 63 72 79 70 74 65 64 20 74 68 65 20 77 68 6f 6c 65 20 64 6f 6d 61 69 6e } //1 deleted all your backups and crypted the whole domain
		$a_01_2 = {5c 63 72 79 70 74 6f 72 2e 70 64 62 } //1 \cryptor.pdb
		$a_01_3 = {71 54 6f 78 20 6d 65 73 73 65 6e 67 65 72 } //1 qTox messenger
		$a_01_4 = {52 53 41 32 } //1 RSA2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}