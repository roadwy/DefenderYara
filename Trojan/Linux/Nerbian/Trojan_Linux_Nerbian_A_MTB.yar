
rule Trojan_Linux_Nerbian_A_MTB{
	meta:
		description = "Trojan:Linux/Nerbian.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 c7 01 49 89 fb 49 c1 e3 04 66 0f 6f 0d 40 cc 22 00 48 01 c2 31 c9 31 f6 66 0f 1f 84 00 00 00 00 00 66 0f 6f 04 0a 48 83 c6 01 66 0f ef c1 0f 29 04 0a 48 83 c1 10 48 39 fe } //1
		$a_03_1 = {48 83 fa 0e 0f ?? ?? ?? ?? ?? 80 70 0e 2e 41 b8 96 01 00 00 41 b9 0f 00 00 00 bf 95 01 00 00 41 ba a5 01 00 00 48 29 d7 49 29 d2 48 c1 ef 04 48 83 c7 01 49 89 fb 49 c1 e3 04 66 0f 6f 0d 40 cc 22 00 48 01 c2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}