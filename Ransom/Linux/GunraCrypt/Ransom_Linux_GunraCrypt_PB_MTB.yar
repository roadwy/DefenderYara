
rule Ransom_Linux_GunraCrypt_PB_MTB{
	meta:
		description = "Ransom:Linux/GunraCrypt.PB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //4 Your data has been encrypted
		$a_01_1 = {52 33 41 44 4d 33 2e 74 78 74 } //1 R3ADM3.txt
		$a_01_2 = {25 73 2f 25 73 2e 6b 65 79 73 74 6f 72 65 } //1 %s/%s.keystore
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}