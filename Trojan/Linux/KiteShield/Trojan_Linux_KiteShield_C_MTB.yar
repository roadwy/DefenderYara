
rule Trojan_Linux_KiteShield_C_MTB{
	meta:
		description = "Trojan:Linux/KiteShield.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 1e fa 49 89 f9 49 89 f2 41 89 d3 45 31 c0 48 c7 c0 0a 00 00 00 4c 89 cf 4c 89 d6 44 89 da 0f 05 41 89 c0 44 89 c0 c3 0f 1f 80 00 00 00 00 f3 0f 1e fa 41 54 41 89 f9 41 89 f3 49 89 d4 45 31 c0 48 c7 c0 65 00 00 00 44 89 cf 44 89 de 4c 89 e2 49 89 ca 0f 05 49 89 c0 4c 89 c0 41 5c c3 f3 0f 1e fa 41 54 41 89 f9 49 89 f3 41 89 d4 45 31 c0 48 c7 c0 3d 00 00 00 44 89 cf 4c 89 de 44 89 e2 49 c7 c2 00 00 00 00 0f 05 41 89 c0 44 89 c0 } //1
		$a_01_1 = {44 89 cf 4c 89 de 4c 89 e2 49 89 ca 0f 05 41 89 c0 44 89 c0 41 5c c3 66 66 2e 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 41 54 41 89 fb 49 89 d4 45 31 c9 55 48 89 f5 53 4c 89 c3 48 c7 c0 9d 00 00 00 44 89 df 48 89 ee 4c 89 e2 49 89 ca 49 89 d8 0f 05 41 89 c1 5b 44 89 c8 5d 41 5c c3 66 0f 1f 44 00 00 f3 0f 1e fa 49 89 f9 49 89 f2 45 31 c0 48 c7 c0 04 00 00 00 4c 89 cf 4c 89 d6 0f 05 41 89 c0 44 89 c0 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}