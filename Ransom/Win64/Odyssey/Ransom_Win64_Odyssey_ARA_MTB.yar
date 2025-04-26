
rule Ransom_Win64_Odyssey_ARA_MTB{
	meta:
		description = "Ransom:Win64/Odyssey.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 6e 65 72 6f 20 41 64 64 72 65 73 73 } //2 Monero Address
		$a_01_1 = {48 61 63 6b 65 64 20 42 79 20 4e 65 74 58 } //2 Hacked By NetX
		$a_01_2 = {5c 52 61 6e 73 6f 6d 57 61 72 65 2d 65 6e 63 72 79 70 74 2e 70 64 62 } //2 \RansomWare-encrypt.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}