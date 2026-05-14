
rule Trojan_BAT_Rozena_AYB_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {4a 3e 97 94 9f 1a dd a9 e7 82 99 66 f6 db e8 7a a0 2c 00 93 f5 dc a9 ff 69 3b fb 07 a8 f0 ce dc ca eb 68 b7 21 1a 06 5a af 46 6a 0a d6 f3 0d 90 84 44 de 39 90 91 3a 61 79 72 df 45 0a d6 95 8b f8 fa 2a 8e d1 8a d1 24 97 63 56 d4 11 18 64 47 69 47 17 11 cc 01 44 65 a5 99 51 83 b2 71 ad 85 39 be 16 dc be 44 20 ae 7c 6a 0b 21 cd b0 e3 67 7f 35 6d e8 } //7
		$a_01_1 = {43 72 79 70 74 65 64 2e 70 64 62 } //2 Crypted.pdb
		$a_01_2 = {70 61 79 6c 6f 61 64 } //2 payload
		$a_01_3 = {43 72 79 70 74 65 64 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 Crypted.g.resources
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=12
 
}