
rule Ransom_Win64_Newcryptor_YAE_MTB{
	meta:
		description = "Ransom:Win64/Newcryptor.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_1 = {59 00 6f 00 75 00 72 00 20 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 69 00 73 00 20 00 68 00 61 00 63 00 6b 00 65 00 64 00 } //10 Your network is hacked
		$a_01_2 = {66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //10 files are encrypted
		$a_01_3 = {6e 65 77 63 72 79 70 74 6f 72 2e 70 64 62 } //1 newcryptor.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1) >=22
 
}