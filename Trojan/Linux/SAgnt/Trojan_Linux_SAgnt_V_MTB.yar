
rule Trojan_Linux_SAgnt_V_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.V!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 31 ed 48 89 e7 48 8d 35 2a 46 27 00 48 83 e4 f0 e8 00 00 00 00 48 81 ec 90 01 00 00 8b 07 49 89 f8 48 89 f1 ff c0 48 98 } //1
		$a_01_1 = {44 89 fa 31 c0 48 89 54 24 08 e8 9f 4e 06 00 44 89 ff 48 89 04 24 e8 6e d9 06 00 31 c0 e8 8c 4e 06 00 48 8b 0c 24 48 8b 54 24 08 48 29 c8 78 78 66 0f ef c0 f2 48 0f 2a c0 } //1
		$a_01_2 = {4c 8d 25 96 03 00 00 4c 89 e7 e8 ce 50 06 00 4c 89 e7 48 8d 74 24 18 e8 f1 50 06 00 41 89 c4 85 c0 75 a1 48 83 7c 24 18 00 0f 84 06 01 00 00 80 3d 4f 49 27 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}