
rule Trojan_Linux_SamDust_A_MTB{
	meta:
		description = "Trojan:Linux/SamDust.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 4c 8d 05 01 17 0b 00 48 8d 0d 8a 16 0b 00 48 8d 3d 15 12 00 00 e8 0e fe ff ff } //1
		$a_01_1 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 4c 8d 05 7a 4f 0b 00 48 8d 0d 03 4f 0b 00 48 8d 3d f7 4d 00 00 ff 15 ae 24 30 00 } //1
		$a_01_2 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 4c 8d 05 44 1f 09 00 48 8d 0d cd 1e 09 00 48 8d 3d 96 ff ff ff e8 81 f5 ff ff } //1
		$a_01_3 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 4c 8d 05 21 04 0c 00 48 8d 0d aa 03 0c 00 48 8d 3d 65 54 00 00 e8 de fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}