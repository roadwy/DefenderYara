
rule Ransom_Win64_Bodegun_YAA_MTB{
	meta:
		description = "Ransom:Win64/Bodegun.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 64 79 73 73 65 79 2d 52 61 6e 73 6f 6d 57 61 72 65 5c 52 61 6e 73 6f 6d 57 61 72 65 2d 65 6e 63 72 79 70 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 52 61 6e 73 6f 6d 57 61 72 65 2d 65 6e 63 72 79 70 74 2e 70 64 62 } //1 Odyssey-RansomWare\RansomWare-encrypt\x64\Release\RansomWare-encrypt.pdb
		$a_01_1 = {59 6f 75 72 20 46 69 6c 65 73 20 48 61 76 65 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 } //1 Your Files Have Been Encrypted
		$a_01_2 = {52 45 41 44 4d 45 2e 74 78 74 } //1 README.txt
		$a_01_3 = {48 61 63 6b 65 64 20 42 79 20 4e 65 74 58 } //1 Hacked By NetX
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}